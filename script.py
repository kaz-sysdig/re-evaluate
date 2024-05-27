import requests
import json
import os
from datetime import datetime, timedelta

SECURE_API = os.getenv('SECURE_API')
SECURE_URL = os.getenv('SECURE_URL')
#
# Step 1: Fetch data from the first API and extract imageDigest and fullTag
#
print("Step 1: Fetching policy evaluation results...")
url = f"https://{SECURE_URL}/api/scanning/v1/resultsDirect?limit=10000&offset=0&sort=desc&sortBy=scanDate"
headers = {
    "Authorization": f"Bearer {SECURE_API}"
}
response = requests.get(url, headers=headers, verify=True)

if response.status_code == 200:
    log1_data = response.json()
else:
    print(f"Failed to fetch data: {response.status_code}")
    log1_data = {}

dict1 = {}
if 'results' in log1_data:
    for result in log1_data['results']:
        image_digest = result['imageDigest']
        full_tag = result['fullTag']
        dict1[image_digest] = full_tag

print("Step 1: Completed successfully. Proceeding to Step 2...")

#
# Step 2: Fetch policy evaluation data and populate dict2
#
print("Step 2: Fetching policy evaluation results with last evaluated at...")
dict2 = {}

for image_digest, full_tag in dict1.items():
    policy_url = f"https://{SECURE_URL}/api/scanning/v1/images/{image_digest}/policyEvaluation?tag={full_tag}"
    response = requests.get(policy_url, headers=headers, verify=True)

    if response.status_code == 200:
        policy_data = response.json()
        at_epoch = policy_data.get('at', None)
        if at_epoch:
            at_time = datetime.fromtimestamp(at_epoch).isoformat()
            dict2[image_digest] = {
                'tag': full_tag,
                'at_epoch': at_epoch,
                'at': at_time
            }
    else:
        print(f"Failed to fetch policy evaluation for {image_digest}: {response.status_code}")

print("Step 2: Completed successfully. Proceeding to Step 3...")


#
# Step 3: Compare epoch times and add flag if difference is more than N hours
#
print("Step 3: Comparing last evaluated at and current time...")

current_time = datetime.now()
current_time_epoch = int(current_time.timestamp())
for key, value in dict2.items():
    at_time = datetime.fromtimestamp(value['at_epoch'])
    value['current_time_epoch'] = current_time_epoch
    value['current_time'] = current_time.isoformat()
    #if (current_time_epoch - value['at_epoch']) > 1800:  #30mins
    if (current_time_epoch - value['at_epoch']) > 86400:  # 24 hours * 60 minutes * 60 seconds
        value['flag'] = True
    else:
        value['flag'] = False

print("Step 3: Completed successfully. Proceeding to Step 4...")


# Step 4: Perform the API call for image re evaluation
print("Step 4: Performing the image re-evaluation...")
reevaluate_attempts = 0
reevaluate_successes = 0
reevaluate_failures = 0

for image_digest, details in dict2.items():
    if details.get('flag'):
        reevaluate_attempts += 1
        req_url = f"https://{SECURE_URL}/api/scanning/v1/anchore/images/by_id/{image_digest}/check?detail=false&forceReload=true&tag={details['tag']}&detail=false"
        req_response = requests.get(req_url, headers=headers, verify=True)

        if req_response.status_code == 200:
            req_data = req_response.json()
            details['req_check'] = req_data
            reevaluate_successes += 1
        else:
            print(f"Failed to fetch the check for {image_digest}: {req_response.status_code}")
            reevaluate_failures += 1

# Output dict2
print(json.dumps(dict2, indent=4))

# Display summary information
print("\nSummary:")
print(f"Step 1: Number of images found: {len(dict1)}")
print(f"Step 4: Number of images re-evaluated: {reevaluate_attempts}")
print(f"Step 4: Number of re-evaluate attempts: {reevaluate_attempts}")
print(f"Step 4: Number of successful re-evaluations: {reevaluate_successes}")
print(f"Step 4: Number of failed re-evaluations: {reevaluate_failures}")
