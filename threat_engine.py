import os
import requests
import json
import re
import base64
import urllib.parse
from datetime import datetime
from dotenv import load_dotenv
import anthropic

# 1. Load Environment Variables
load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")

# 2. Initialize the Anthropic Client
client = anthropic.Anthropic(
    api_key=ANTHROPIC_API_KEY,
    base_url=os.getenv("ANTHROPIC_BASE_URL"),
    timeout=60.0 # Global safety net for the connection
)

# --- UPGRADE 1: URL DEFANGING ---
def defang_indicator(indicator_string):
    """Makes URLs and IPs unclickable for safety."""
    defanged = indicator_string.replace(".", "[.]")
    defanged = defanged.replace("http", "hxxp")
    return defanged

# --- UPGRADE 2: DEDICATED OCR ENGINE ---
def extract_text_with_vision(image_bytes):  
    """Uses a dedicated OCR engine to extract text from screenshots."""
    print("[*] Bypassing broken LLM Vision. Routing to dedicated OCR Engine...")
    
    try:
        response = requests.post(
            'https://api.ocr.space/parse/image',
            
            files={'file': ('image.jpg', image_bytes, 'image/jpeg')}, 
            data={
                'apikey': 'helloworld', 
                'language': 'eng',
                'detectOrientation': 'true',
                'scale': 'true'
            },
            timeout=15.0
        )
        
        # Shield against HTML error pages (502, 503, etc.)
        if response.status_code != 200:
            print(f"[-] OCR Server Error {response.status_code}: {response.text[:100]}")
            return None
            
        result = response.json()
        
        if result.get('IsErroredOnProcessing'):
            print(f"[-] OCR Processing Error: {result.get('ErrorMessage')}")
            return None
            
        extracted_text = result['ParsedResults'][0]['ParsedText']
        return extracted_text
        
    except Exception as e:
        print(f"[-] OCR API Error: {e}")
        return None

# 3. Extraction Engine
def extract_indicator(text):
    """Scans text and prioritizes URLs, then falls back to IP addresses."""
    # NEW REGEX: Increased the domain extension limit to 24 to catch things like .online or .technology
    url_pattern = r'(?:https?://)?(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{2,24}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)'
    url_match = re.search(url_pattern, text)
    if url_match and "@" not in url_match.group(0): 
        return {'type': 'url', 'value': url_match.group(0)}

    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    ip_match = re.search(ip_pattern, text)
    if ip_match:
        return {'type': 'ip', 'value': ip_match.group(0)}
        
    return None

# 4. Threat Intelligence API Calls (WITH TIMEOUTS)
def scan_ip_virustotal(ip_address):
    print(f"[*] Scanning IP: {ip_address}...")
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {"accept": "application/json", "x-apikey": VT_API_KEY}
    try:
        response = requests.get(url, headers=headers, timeout=5.0) 
        return response.json() if response.status_code == 200 else None
    except Exception as e: 
        print(f"[-] VT IP Scan Error: {e}")
        return None

def scan_url_virustotal(target_url):
    print(f"[*] Scanning URL: {target_url}...")
    url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
    url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"accept": "application/json", "x-apikey": VT_API_KEY}
    try:
        response = requests.get(url, headers=headers, timeout=5.0)
        return response.json() if response.status_code == 200 else None
    except Exception as e: 
        print(f"[-] VT URL Scan Error: {e}")
        return None

# 5. AI Reasoning Engine
def analyze_with_glm(email_text, threat_data):
    """Forces the AI to act as a Security Analyst and extracts JSON safely."""
    print("\n[*] Sending context to live ilmu-glm-5.1 for analysis...")
    
    try:
        stats = threat_data['data']['attributes']['last_analysis_stats']
    except KeyError:
        stats = {"error": "Could not parse VT data."}
    
    truncated_text = email_text[:300]  
    
    # Uses the OpSec rule and asks for standard JSON output
    combined_prompt = f"""You are a Security Operations Center Analyst.
Analyze the threat data. You MUST output a JSON object containing your analysis.

CRITICAL OPSEC RULE: You are STRICTLY FORBIDDEN from writing the actual URL, domain name, or IP address inside your `reasoning`. 
If you must reference it, use the exact phrase "the suspicious link" or "the target domain". Do not attempt to defang it; simply omit it entirely.

-- USER INPUT --
{truncated_text}

-- THREAT DATA --
{json.dumps(stats)}

Output ONLY a valid JSON object matching this exact schema:
{{
    "threat_level": "Low",
    "confidence_score": 90,
    "reasoning": "brief explanation",
    "recommended_action": "Block IP"
}}"""

    print(f"[DEBUG] Sending request to AI...")
    
    try:
        response = client.messages.create(
            model="ilmu-glm-5.1", 
            max_tokens=1024,  # Keep the massive breathing room
            temperature=0.1,  
            messages=[
                {"role": "user", "content": combined_prompt} 
            ]
        )
        
        raw_response = response.content[0].text
        print(f"[DEBUG] Raw response: {raw_response}")
        
        # --- THE BULLETPROOF REGEX EXTRACTOR ---
        # This searches the AI's response and grabs everything from { to }
        match = re.search(r'\{.*\}', raw_response, re.DOTALL)
        
        if match:
            clean_json = match.group(0)
            print(f"[DEBUG] Extracted JSON: {clean_json}")
            return clean_json
        else:
            print(f"[-] AI did not return any JSON brackets! It said: {raw_response}")
            return None
            
    except anthropic.APITimeoutError as e:
        print(f"[-] AI TIMEOUT after 60 seconds: {e}")
        return None
    except anthropic.APIConnectionError as e:
        print(f"[-] AI CONNECTION ERROR: {e}")
        return None
    except anthropic.AuthenticationError as e:
        print(f"[-] AI AUTH ERROR: {e}")
        return None
    except Exception as e:
        print(f"[-] UNEXPECTED ERROR: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return None