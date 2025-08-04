import requests
import hashlib

def gravatar_check(email):
    email = email.strip().lower().encode('utf-8')
    gravatar_hash = hashlib.md5(email).hexdigest()
    gravatar_url = f"https://www.gravatar.com/avatar/{gravatar_hash}?d=404"
    response = requests.get(gravatar_url)
    if response.status_code == 200:
        return gravatar_url
    return None

def hibp_check(email, hibp_api_key):
    headers = {
        'hibp-api-key': hibp_api_key,
        'user-agent': 'OSINT-Collector'
    }
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    elif response.status_code == 404:
        return []  # No breach found
    else:
        return {"error": f"Error {response.status_code}: {response.text}"}

def run_email_recon(email, hibp_api_key=None):
    results = {}

    print(f"[+] Running email recon on: {email}")
    gravatar = gravatar_check(email)
    if gravatar:
        results['gravatar'] = gravatar
        print(f"[+] Gravatar found: {gravatar}")
    else:
        print("[-] No Gravatar found.")

    if hibp_api_key:
        breaches = hibp_check(email, hibp_api_key)
        results['breaches'] = breaches
        if isinstance(breaches, list) and breaches:
            print(f"[!] Found {len(breaches)} breach(es) in HIBP:")
            for breach in breaches:
                print(f"  - {breach['Name']} ({breach['BreachDate']})")
        elif not breaches:
            print("[+] No breaches found in HIBP.")
        else:
            print(f"[!] Error checking HIBP: {breaches.get('error')}")
    else:
        print("[!] Skipping HIBP check (no API key provided)")

    return results
