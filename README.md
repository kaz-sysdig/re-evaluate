Sysdig Vulnerability re evaluation code sample

## Parameters
```
# Your Sysdig Secure API Endpoint
export SECURE_URL=app.us4.sysdig.com

# Your Sysdig Secure API Token
export SECURE_API=1c708a83-e413-4c45-87fc-9df23163cxxx

# Time diff between last evaluated at and current time
export TIME_DIFF=86400
```

## Usage
```
pip3 install -r requirements
python3 force_evaluate.py
```

## Docker
```
docker build -t force_evaluate .
dockr run --rm \
 -e SECURE_URL={YOUR_SECURE_API_ENDPOINT} \
 -e SECURE_API={YOUR_SECURE_API_TOKEN} \
 -e TIME_DIFF={Time diff between last evaluated at and current time} \
 force_evaluate
```

## Kubernetes
```
# Create a secret for SECURE_API
echo -n '503ae4b0-eefh-4cah-baeh-eeeeelfeeee7' | base64

# Set the secret value in secret.yaml
% vi secret.yaml
SECURE_API: {SECURE_API_TOKEN}

# Set values in cronjob.yaml
% vi secret.yaml
secret
- SECURE_API
env
- {YOUR_SECURE_URL}
- {TIME_DIFF}

# create secret and cronjob
kubectl apply -f secret.yaml
kubectl apply -f cronjob.yaml
```

## Example output
```
Step 1: Fetching policy evaluation results...
Step 1: Completed successfully. Proceeding to Step 2...
Step 2: Fetching policy evaluation results with last evaluated at...
Step 2: Completed successfully. Proceeding to Step 3...
Step 3: Comparing last evaluated at and current time...
Step 3: Completed successfully. Proceeding to Step 4...
Step 4: Performing the image re-evaluation...
{
    "sha256:a484819eb60211f5299034ac80f6a681b06f89e65866ce91f356ed7c72af059c": {
        "tag": "docker.io/library/nginx:latest",
        "at_epoch": 1716788222,
        "at": "2024-05-27T05:37:02",
        "current_time_epoch": 1716790058,
        "current_time": "2024-05-27T06:07:38.837191",
        "flag": true,
        "req_check": [
            {
                "sha256:a484819eb60211f5299034ac80f6a681b06f89e65866ce91f356ed7c72af059c": {
                    "docker.io/library/nginx:latest": [
                        {
                            "detail": {},
                            "last_evaluation": "2024-05-27T06:07:39Z",
                            "policyId": "default",
                            "status": "pass"
                        }
                    ]
                }
            }
        ]
    },
    "sha256:70e40e3ca545f637c03817ec76a9a4d8e9667a8a11fdafba6a7b34c56d27cee5": {
        "tag": "quay.io/sysdig/host-analyzer:0.1.19",
        "at_epoch": 1716788314,
        "at": "2024-05-27T05:38:34",
        "current_time_epoch": 1716790058,
        "current_time": "2024-05-27T06:07:38.837191",
        "flag": false
    }
}

Summary:
Step 1: Number of images found: 64
Step 4: Number of images re-evaluated: 20
Step 4: Number of re-evaluate attempts: 20
Step 4: Number of successful re-evaluations: 20
Step 4: Number of failed re-evaluations: 0
```
