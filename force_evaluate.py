import requests
import json
import os
from datetime import datetime, timedelta
import logging

logging.basicConfig(level=logging.DEBUG)
logging.getLogger("urllib3").setLevel(logging.DEBUG)
logging.getLogger("requests").setLevel(logging.DEBUG)

SECURE_API = os.getenv('SECURE_API')
SECURE_URL = os.getenv('SECURE_URL')
TIME_DIFF = os.getenv('TIME_DIFF')
TIME_DIFF = int(TIME_DIFF)

if not SECURE_API or not SECURE_URL:
    raise ValueError("SECURE_API and SECURE_URL environment variables must be set")

def check_rocky_version(dict1):
    """Step 1.5: Get the distro info from images"""
    print("Step 1.5: Getting the distro info...", flush=True)
    for image_key, details in dict1.items():
        full_tag = details['full_tag']
        image_id = details['image_id']
        url = f"https://{SECURE_URL}/api/scanning/v1/images/by_id/{image_id}/?fulltag={full_tag}"
        headers = {
            "Authorization": f"Bearer {SECURE_API}"
        }
        response = requests.get(url, headers=headers, verify=False)

        if response.status_code == 200:
            data = response.json()
            for key, value in data.items():
                if key == 'distro' and value == 'rocky':
                    if data.get('distroVersion', '').startswith('9'):
                        print(f"Found Rocky Linux 9.x: {data['fullTag']}")
                        details['is_rocky_9'] = 1
                        details['distro'] = data.get('distro')
                        details['distroVersion'] = data.get('distroVersion')
                    else:
                        print("This is Rocky Linux but not version 9.x")
                        details['is_rocky_9'] = 0
                        details['distro'] = data.get('distro')
                        details['distroVersion'] = data.get('distroVersion')
        else:
            print(f"Failed to fetch data: {response.status_code}", flush=True)
            data = {}

    print("Step 1.5: Completed successfully. Proceeding to Step 2...", flush=True)
    print(json.dumps(dict1, indent=4), flush=True)
    print("---------------------------------------------------------------------")
    return dict1

def fetch_policy_evaluation_results():
    """Step 1: Fetch data from the first API and extract imageDigest and fullTag"""
    print("Step 1: Fetching policy evaluation results...", flush=True)
    url = f"https://{SECURE_URL}/api/scanning/v1/resultsDirect?limit=10000&offset=0&sort=desc&sortBy=scanDate"
    headers = {
        "Authorization": f"Bearer {SECURE_API}"
    }
    response = requests.get(url, headers=headers, verify=False)

    if response.status_code == 200:
        log1_data = response.json()
    else:
        print(f"Failed to fetch data: {response.status_code}", flush=True)
        log1_data = {}

    dict1 = {}
    if 'results' in log1_data:
        for result in log1_data['results']:
            full_tag = result['fullTag']
            image_digest = result['imageDigest']
            image_id = result['imageId']
            image_key = f"{full_tag}-{image_id}"
            dict1[image_key] = {'image_id': image_id, 'image_digest': image_digest, 'full_tag': full_tag}

    print("Step 1: Completed successfully. Proceeding to Step 1.5...", flush=True)
    print(json.dumps(dict1, indent=4), flush=True)
    print("---------------------------------------------------------------------")
    return dict1

def fetch_policy_evaluation_data(dict1):
    """Step 2: Fetch policy evaluation data and populate dict2"""
    print("Step 2: Fetching policy evaluation results with last evaluated at...", flush=True)
    dict2 = {}

    #for full_tag, image_id in dict1.items():
    for image_key, details in dict1.items():
        is_rocky_9 = details['is_rocky_9']
        full_tag = details['full_tag']
        image_id = details['image_id']
        image_digest = details['image_digest']
        policy_url = f"https://{SECURE_URL}/api/scanning/v1/images/{image_digest}/policyEvaluation?tag={full_tag}"
        headers = {
            "Authorization": f"Bearer {SECURE_API}"
        }
        response = requests.get(policy_url, headers=headers, verify=False)

        if response.status_code == 200:
            policy_data = response.json()
            at_epoch = policy_data.get('at', None)
            if at_epoch:
                at_time = datetime.fromtimestamp(at_epoch).isoformat()
                dict2[image_key] = {
                    'image_digest': image_digest,
                    'image_id': image_id,
                    'tag': full_tag,
                    'at_epoch': at_epoch,
                    'at': at_time,
                    'is_rocky_9' : is_rocky_9
                }
        else:
            print(f"Failed to fetch policy evaluation for {image_digest}: {response.status_code}", flush=True)

    print("Step 2: Completed successfully. Proceeding to Step 3...", flush=True)
    print(json.dumps(dict2, indent=4), flush=True)
    return dict2

def compare_epoch_times(dict2):
    """Step 3: Compare epoch times and add flag if difference is more than N seconds"""
    print("Step 3: Comparing last evaluated at and current time...", flush=True)

    current_time = datetime.now()
    current_time_epoch = int(current_time.timestamp())
    for key, value in dict2.items():
        value['current_time_epoch'] = current_time_epoch
        value['current_time'] = current_time.isoformat()
        if (current_time_epoch - value['at_epoch']) > TIME_DIFF:
            value['flag'] = True
        else:
            value['flag'] = False

    print("Step 3: Completed successfully. Proceeding to Step 4...", flush=True)
    return dict2

def perform_image_re_evaluation(dict2):
    """Step 4: Perform the API call for image re-evaluation"""
    print("Step 4: Performing the image re-evaluation...", flush=True)
    reevaluate_attempts = 0
    reevaluate_successes = 0
    reevaluate_failures = 0

    for image_key, details in dict2.items():
        if details.get('flag') and details.get('is_rocky_9') == 0:
            reevaluate_attempts += 1
            req_url = f"https://{SECURE_URL}/api/scanning/v1/anchore/images/by_id/{details['image_digest']}/check?detail=false&forceReload=true&tag={details['tag']}&detail=false"
            headers = {
                "Authorization": f"Bearer {SECURE_API}"
            }
            req_response = requests.get(req_url, headers=headers, verify=False)

            if req_response.status_code == 200:
                req_data = req_response.json()
                details['req_check'] = req_data
                reevaluate_successes += 1
            else:
                print(f"Failed to fetch the check for {image_digest}: {req_response.status_code}", flush=True)
                reevaluate_failures += 1

    # Output dict2
    print(json.dumps(dict2, indent=4), flush=True)

    # Display summary information
    print("\nSummary:", flush=True)
    print(f"Step 1: Number of images found: {len(dict2)}", flush=True)
    print(f"Step 4: Number of images re-evaluated: {reevaluate_attempts}", flush=True)
    print(f"Step 4: Number of re-evaluate attempts: {reevaluate_attempts}", flush=True)
    print(f"Step 4: Number of successful re-evaluations: {reevaluate_successes}", flush=True)
    print(f"Step 4: Number of failed re-evaluations: {reevaluate_failures}", flush=True)

def main():
    dict1 = fetch_policy_evaluation_results()
    dict1 = check_rocky_version(dict1)
    dict2 = fetch_policy_evaluation_data(dict1)
    dict2 = compare_epoch_times(dict2)
    perform_image_re_evaluation(dict2)

if __name__ == "__main__":
    main()
