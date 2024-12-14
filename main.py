import re  # re module is used for regular expressions, which helps validate IP addresses in this script.
import pandas as pd  # pandas library is used for working with structured data, such as the SIEM logs stored in CSV files.
import requests  # requests library is used for making HTTP requests to APIs like VirusTotal and AlienVault OTX.
from dotenv import load_dotenv
import os

# Load .env variables
load_dotenv()

# Access API keys
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ALIENVAULT_API_KEY = os.getenv("ALIENVAULT_API_KEY")

if not VIRUSTOTAL_API_KEY or not ALIENVAULT_API_KEY:
    raise EnvironmentError(
        "API keys for VirusTotal or AlienVault are missing. Check your .env file."
    )


# Function to query VirusTotal
def query_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    # Headers: Passes the API key in the headers to authenticate the request.
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    # Request: Sends a GET request to the VirusTotal API.
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        # Retrieves the last_analysis_stats attribute, which contains scan results.
        return data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    # If the request fails, it returns an error with the HTTP status code.
    return {"error": response.status_code}


# Function to query AlienVoult OTX
def query_alienvault(ip):
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    headers = {"X-OTX-API-KEY": ALIENVAULT_API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        # If successful, it retrieves the pulse_info.count field, representing the number of threat intelligence "pulses" associated with the IP.
        return data.get("pulse_info", {}).get("count", 0)
    return {"error": response.status_code}


# Function to validate IP addresses
def validate_ip(ip):
    # Regular Expression: The ip_pattern checks if the input string is a valid IPv4 address (e.g., 192.168.1.1).
    ip_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    # Validation: The re.match() function checks if the ip matches the pattern. Returns True if valid, otherwise False.
    return re.match(ip_pattern, ip) is not None


# Main function to enrich SIEM logs
def enrich_logs(log_file):
    # Load logs into pandas DataFrame
    # Reads the input CSV log file using pd.read_csv()
    logs = pd.read_csv(log_file)

    # Add new columns for enrichment
    logs["vt_analysis_stats"] = None
    logs["otx_pulse_count"] = None

    # Enrich each log entry
    # Uses iterrows() to loop through each row of the DataFrame.
    for index, row in logs.iterrows():
        source_ip = row["source_ip"]
        # Validates the source_ip using validate_ip().
        if validate_ip(source_ip):
            print(f"Processing {source_ip}...")
            # Updates the new columns using logs.at[index, column_name].
            logs.at[index, "vt_analysis_stats"] = query_virustotal(source_ip)
            logs.at[index, "otx_pulse_count"] = query_alienvault(source_ip)

    # Save enriched logs
    logs.to_csv("enriched_logs.csv", index=False)


# Run the script
# Entry Point: This block runs only when the script is executed directly (not imported).

if __name__ == "__main__":
    log_file = "logs.csv"  # Input log file
    enrich_logs(log_file)  # Function Call: Calls enrich_logs() with the file as input.
