Sysdig Vulnerability re evaluation code sample

## Parameters
```
# Your Sysdig Secure API Endpoint
export SECURE_URL=app.us4.sysdig.com

# Your Sysdig Secure API Token
export SECURE_API=1c708a83-e413-4c45-87fc-9df23163cxxx
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
 force_evaluate
```

## Example output
```
```
