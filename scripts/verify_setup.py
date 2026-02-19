import time
import sys
import json
import urllib.request
import urllib.error
import urllib.parse

BASE_URL = "http://localhost:8000/api/v1"

def make_request(method, url, data=None, headers=None):
    if headers is None:
        headers = {}
    
    if data is not None:
        data_bytes = json.dumps(data).encode('utf-8')
        headers['Content-Type'] = 'application/json'
    else:
        data_bytes = None

    req = urllib.request.Request(url, data=data_bytes, headers=headers, method=method)
    
    try:
        with urllib.request.urlopen(req) as response:
            return {
                'status': response.status,
                'headers': response.headers,
                'body': response.read().decode('utf-8')
            }
    except urllib.error.HTTPError as e:
        return {
            'status': e.code,
            'headers': e.headers,
            'body': e.read().decode('utf-8')
        }
    except Exception as e:
        print(f"Request error: {e}")
        return None

def wait_for_api():
    print("Waiting for API to be ready...")
    for _ in range(30):
        try:
            # Check setup status endpoint which should be available
            resp = make_request("GET", f"{BASE_URL}/setup/status")
            if resp and resp['status'] == 200:
                print("API is ready.")
                return True
        except:
            pass
        time.sleep(2)
    print("API failed to become ready.")
    return False

def test_cors_pre_setup():
    print("Testing CORS before setup (should allow all)...")
    origin = "http://random-origin.com"
    headers = {
        "Origin": origin, 
        "Access-Control-Request-Method": "GET"
    }
    resp = make_request("OPTIONS", f"{BASE_URL}/health", headers=headers)
    
    if not resp:
        return False
        
    allow_origin = resp['headers'].get("access-control-allow-origin")
    print(f"Origin: {origin}, Allow-Origin: {allow_origin}")
    
    if allow_origin != origin and allow_origin != "*":
         print("FAIL: Expected allow-origin to match request or be *")
         return False
    return True

def perform_setup():
    print("Performing setup...")
    payload = {
        "admin_email": "admin@example.com",
        "admin_password": "SecurePassword123!",
        "llm_provider": "openai",
        "llm_api_key": "sk-dummy-key",
        "llm_model": "gpt-4o",
        "allowed_origins": ["http://localhost:5173", "https://my-domain.com"]
    }
    
    resp = make_request("POST", f"{BASE_URL}/setup", data=payload)
    
    if not resp or (resp['status'] != 200 and resp['status'] != 201):
        print(f"Setup failed: {resp['status'] if resp else 'No response'}")
        if resp: print(resp['body'])
        return False
    print("Setup completed successfully.")
    return True

def test_cors_post_setup():
    print("Testing CORS after setup...")
    
    # allowed origin
    origin1 = "http://localhost:5173"
    resp1 = make_request("OPTIONS", f"{BASE_URL}/health", headers={"Origin": origin1, "Access-Control-Request-Method": "GET"})
    
    if not resp1 or resp1['headers'].get("access-control-allow-origin") != origin1:
        print(f"FAIL: Expected {origin1} to be allowed. Got {resp1['headers'].get('access-control-allow-origin') if resp1 else 'None'}")
        return False

    # allowed origin 2
    origin2 = "https://my-domain.com"
    resp2 = make_request("OPTIONS", f"{BASE_URL}/health", headers={"Origin": origin2, "Access-Control-Request-Method": "GET"})
    
    if not resp2 or resp2['headers'].get("access-control-allow-origin") != origin2:
        print(f"FAIL: Expected {origin2} to be allowed. Got {resp2['headers'].get('access-control-allow-origin') if resp2 else 'None'}")
        return False
        
    # disallowed origin
    origin3 = "http://evil.com"
    resp3 = make_request("OPTIONS", f"{BASE_URL}/health", headers={"Origin": origin3, "Access-Control-Request-Method": "GET"})
    
    if resp3 and resp3['headers'].get("access-control-allow-origin"):
        print(f"FAIL: Expected {origin3} to NOT be allowed. Got: {resp3['headers'].get('access-control-allow-origin')}")
        return False

    print("CORS Post-Setup verification passed.")
    return True

if __name__ == "__main__":
    if not wait_for_api():
        sys.exit(1)
    if not test_cors_pre_setup():
        sys.exit(1)
    if not perform_setup():
        sys.exit(1)
    if not test_cors_post_setup():
        sys.exit(1)
    print("ALL TESTS PASSED")
