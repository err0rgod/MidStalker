import argparse
from core.email_recon import run_email_recon
#from utils.api_keys import HIBP_API_KEY

HIBP_API_KEY = "5257:gk-8pyvtYlTds8GmfL_TP4K4IaLzfa4lDUJa5xkdZvvPcrmF5-DEUIjgY992BjwY"

def main():
    parser = argparse.ArgumentParser(description="OSINT Email Recon Tool")
    parser.add_argument("--email", required=True, help="Target email address")
    args = parser.parse_args()

    results = run_email_recon(args.email, hibp_api_key=HIBP_API_KEY)
    print("\n[+] Final Recon Results:")
    for key, value in results.items():
        print(f"  {key}: {value}")

if __name__ == "__main__":
    main()
