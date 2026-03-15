import validators
import requests
import os
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import sys

# --- Google Safe Browsing API Setup ---
# Use environment variable for better security in Open Source
SAFE_BROWSING_API_KEY = os.getenv("SAFE_BROWSING_API_KEY", "GOOGLE_SAFE_BROWSING_API_KEY")

# Define a common browser User-Agent to avoid being blocked
HTTP_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
}

def is_valid_url(url):
    """Check if the URL is syntactically valid."""
    return validators.url(url)

def is_url_reachable(url, timeout=5):
    """Check if the URL is reachable (responds to a request)."""
    try:
        # Step 1: Try HEAD request (fast and efficient)
        response = requests.head(url, 
                                 timeout=timeout, 
                                 allow_redirects=True, 
                                 headers=HTTP_HEADERS)
        
        # Step 2: Fallback to GET if HEAD is not allowed (Status 405 or 403)
        if response.status_code in [403, 405]:
            response = requests.get(url, 
                                    timeout=timeout, 
                                    allow_redirects=True, 
                                    headers=HTTP_HEADERS,
                                    stream=True) # stream=True avoids downloading large body

        print(f"Debug: Status code for {url}: {response.status_code}", file=sys.stderr)
        return response.ok
    except requests.RequestException:
        return False

def check_url_safety(url):
    """Check if the URL is marked as unsafe by Google Safe Browsing."""
    if SAFE_BROWSING_API_KEY == "GOOGLE_SAFE_BROWSING_API_KEY":
        print("Error: SAFE_BROWSING_API_KEY is not set. Skipping safety check.", file=sys.stderr)
        return None

    try:
        # Added cache_discovery=False to avoid potential FileNotFoundError in some environments
        service = build("safebrowsing", "v4", developerKey=SAFE_BROWSING_API_KEY, cache_discovery=False)
        
        payload = {
            "client": {
                "clientId": "my-validation-script",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        
        # Added timeout via execute() is tricky in build(), 
        # but the underlying library usually handles it.
        response = service.threatMatches().find(body=payload).execute()
        
        if response.get("matches"):
            return False
        else:
            return True
            
    except HttpError as e:
        print(f"Error: Google Safe Browsing API call failed: {e}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"Error: An unexpected error occurred during safety check: {e}", file=sys.stderr)
        return None

def validate_url(url):
    """Validate URL, check reachability, and safety."""
    
    # 1. Check syntax
    if not is_valid_url(url):
        return {"valid": False, "url": url, "error": "Invalid URL format."}

    # 2. Check reachability
    if not is_url_reachable(url):
        # Improved: Double-check with HTTP if HTTPS fails
        if url.startswith('https://'):
            http_url = url.replace('https://', 'http://', 1)
            if is_url_reachable(http_url):
                 url = http_url # Update URL to working HTTP version
            else:
                 return {"valid": False, "url": url, "error": "URL is unreachable on both HTTP and HTTPS."}
        else:
            return {"valid": False, "url": url, "error": "URL is unreachable."}

    # 3. Check safety
    is_safe = check_url_safety(url)
    
    if is_safe is False:
        return {"valid": False, "url": url, "error": "Warning: This URL is marked as UNSAFE by Google Safe Browsing!"}
    
    if is_safe is None:
        return {
            "valid": True, 
            "url": url,
            "message": "URL is valid and reachable.",
            "warning": "Could not perform safety check (API error or key issue)."
        }

    return {"valid": True, "url": url, "message": "URL is valid, reachable, and safe."}

if __name__ == "__main__":
    try:
        url_to_test = input("Enter URL to validate: ")
        
        if not url_to_test.startswith(('http://', 'https://')):
            # Strategy: try HTTPS first, then fallback
            url_to_test = 'https://' + url_to_test
            
        result = validate_url(url_to_test)
        print("\n--- Validation Result ---")
        print(result)
        
    except KeyboardInterrupt:
        print("\nValidation cancelled.")
