import requests
import json
import time

# Your VirusTotal API key
VT_API_KEY = "e78856d2592f740d3db4edd474be64b644d39b583a1f2d1c176a7b5e5e664299"

def scan_file(file_path):
    url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": VT_API_KEY}

    with open(file_path, "rb") as file:
        files = {"file": file}
        response = requests.post(url, headers=headers, files=files)

    if response.status_code == 200:
        return response.json()
    else:
        print(f"Failed to get a valid response: HTTP {response.status_code}")
        print("Response text:", response.text)
        return None

def get_analysis_results(analysis_id):
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return response.json()
    else:
        print(f"Failed to get analysis results: HTTP {response.status_code}")
        print("Response text:", response.text)
        return None

def interpret_results(analysis_result):
    stats = analysis_result['data']['attributes']['stats']
    malicious = stats.get('malicious', 0)
    undetected = stats.get('undetected', 0)

    if malicious > 0:
        print("The file is affected by malware.")
    elif undetected > 0:
        print("The file is not affected by any known malware.")
    else:
        print("The analysis did not yield conclusive results.")

# User input for file path
file_path = input("Enter the file path to scan: ")
scan_result = scan_file(file_path)

if scan_result:
    print("File submitted successfully. Fetching analysis results...")
    analysis_id = scan_result["data"]["id"]
    # It might take some time for the analysis to complete, so we wait a bit before fetching the results
    time.sleep(15)  # Wait for 15 seconds; adjust this based on how quickly you need results vs. API rate limits

    analysis_result = get_analysis_results(analysis_id)
    if analysis_result:
        print("Analysis result:")
        print(json.dumps(analysis_result, indent=4))
        interpret_results(analysis_result)
    else:
        print("Failed to get the analysis result.")
else:
    print("Failed to scan the file.")