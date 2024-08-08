import requests
import sys
import re
import os


def get_api_key():
    """
    Retrieves the API key from an environment variable.

    Returns:
    str: The API key, or None if the environment variable is not set.
    Bash 
    export NVI_API_KEY="your-api-key-here"

    """ 
    api_key = os.getenv('NVI_API_KEY')
    if api_key:
        return api_key
    else:
        return None


def process_line(line):
    # Define regex patterns for the different formats
    patterns = [
        r'\[(.*?)\] \[(.*?)\] \[(.*?)\] (http[s]?://\S+)',
        r'\[(.*?)\] \[(.*?)\] \[(.*?)\] (.*?):(\d+) \[(.*?)\]',
        r'\[(.*?)\] \[(.*?)\] \[(.*?)\] (.*?):(\d+)',
        r'\[(.*?)\] \[(.*?)\] \[(.*?)\] (.*?)(?=\s\[\S+\]|\s\[\S+\]\s\[\S+\]|\s\[\S+\]\s\[\S+\]\s\[\S+\]|\s\[\S+\]\s\[\S+\])'
    ]
    
    for pattern in patterns:
        match = re.search(pattern, line)
        if match:
            # Determine which pattern matched and extract relevant information
            if '://' in match.group(4):
                # Handle URL-based entries
                category1 = match.group(1)
                category2 = match.group(2)
                level = match.group(3)
                url = match.group(4)
                
                print(f"Template ID: {category1}")
                print(f"Category: {category2}")
                print(f"Nuclei rating: {level}")
                print(f"URL: {url}")

                if is_valid_cve(category1):
                    category1 = remove_ansi_color_codes(category1)
                    intel = fetch_intel(category1)
                    print(f"Intel: {intel}")
            else:
                # Handle non-URL-based entries
                category1 = match.group(1)
                category2 = match.group(2)
                level = match.group(3)
                hostname = match.group(4)
                port = match.group(5) if len(match.groups()) == 5 else None
                details = match.group(6) if len(match.groups()) == 6 else None
                
                print(f"Template ID: {category1}")
                print(f"Category: {category2}")
                print(f"Nuclei Rating: {level}")
                print(f"Hostname: {hostname}")
                if port:
                    print(f"Port: {port}")
                if details:
                    print(f"Details: {details}")
                
                if is_valid_cve(category1):
                    category1 = remove_ansi_color_codes(category1)
                    intel = fetch_intel(category1)
                    print(f"Intel: {intel}")
     
            print("-" * 40)  # Separator between entries
            return  # Exit after finding the first match
    
    print("No match found or invalid input format")
    print("-" * 40)  # Separator between entries

def fetch_intel(cve):
    token = api_key
    # Define the URL and the headers
    url = "https://service.northinfosec.com/api"
    headers = {
        "token": token,
        "Content-Type": "application/json"
    }
    # Define the body of the POST request
    body = {
        "cveid": [cve]
    }
    # Send the POST request
    response = requests.post(url, json=body, headers=headers)

    # Check if the response is successful
    if response.status_code == 200:
        try:
            # Parse the JSON response
            data = response.json()
            
            #print(data)
            if "message" in data and "code" in data:
                if (data['code']=="0007"):
                    return (f"Not available")
                else:
                    return (f"Access Denied")
            else:

            # Iterate through the list of CVEs
                for cve in data:
                    cveID = cve.get('cveID', 'N/A')
                    risk_rating = cve.get('risk_rating', 'N/A')
                    exploit_lc = cve.get('exploit_lc', 'N/A')
                    ransom = cve.get('ransomware', 'N/A')
                    kev = cve.get('kev', 'N/A')

                    #print(f"cveID: {cveID}, risk_rating: {risk_rating}")
                    return (f"NVI risk_rating => {risk_rating} | Public exploit => {exploit_lc} | Ransomware => {ransom} | kev => {kev} ")
        except ValueError:
            print("Invalid JSON response")
    else:
        print(f"Failed to fetch data. Status code: {response.status_code}")
        print("Response Body:", response.text)

def remove_ansi_color_codes(text):
    """
    Remove ANSI color codes from the given string.
    
    Parameters:
    text (str): The string with ANSI color codes to clean.
    
    Returns:
    str: The string without ANSI color codes.
    """
    # Define the regex pattern for ANSI color codes
    ansi_escape = re.compile(r'\x1b\[[0-9;]*m')
    
    # Substitute the ANSI color codes with an empty string
    return ansi_escape.sub('', text)

def is_valid_cve(cve_id):
    """
    Validate if the given string is a valid CVE identifier.
    
    Parameters:
    cve_id (str): The CVE identifier string to validate.
    
    Returns:
    bool: True if the CVE identifier is valid, False otherwise.
    """
    cve_id = remove_ansi_color_codes(cve_id)

    # Define the regex pattern for a valid CVE identifier
    
    pattern = r'^\[?CVE-\d{4}-\d{4,}\]?$'

    # Use regex to match the CVE identifier
    match = re.match(pattern, cve_id)
    return bool(match)


api_key = get_api_key()

if api_key != None:
    for line in sys.stdin:
        line = line.strip()
        if line:  # Skip empty lines
            process_line(line)
else:
    print("\n API Key not set, make you have declare the API key ENV. export NVI_API_KEY=\"your-api-key-here\" \n ")

