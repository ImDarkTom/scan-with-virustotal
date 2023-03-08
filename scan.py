import os
import sys
import webbrowser

def error(msg):
    print(f"Error: {msg}")
    input("Press any key to exit...")
    sys.exit(1)

def main():

    # Check for command line argument
    if len(sys.argv) < 2:
        error("Please provide a file to scan.")

    # Get file
    file = sys.argv[1]

    # Check if file exists
    if not os.path.exists(file):
        error(f"{file} does not exist. Please provide a valid file to scan.")

    # Get API key
    with open("apikey.txt", "r") as f: 
        apikey = f.read().strip()
        if not apikey:
            error("No VirusTotal API key was found. Please provide one by putting it into the apikey.txt file.")

        elif len(apikey) != 64:
            error("Invalid VirusTotal API key. Please make sure your key is on the first line of the apikey.txt file and 64 characters long.")
        

    # Set up request
    files = {"file": (os.path.basename(file), open(file, "rb"), "application/octet-stream")}
    headers = {
        "accept": "application/json",
        "x-apikey": apikey
    }

    #Send and get response
    print(f"Uploading {file} to VirusTotal... (large files may take a while to upload)")
    try:
        import requests
        response = requests.post("https://www.virustotal.com/api/v3/files", files=files, headers=headers)
        response.raise_for_status()
    
    except requests.exceptions.RequestException as e:
        error(f"Failed to upload file to VirusTotal: {e}")

    respjson = response.json()

    #Open scan ID url in browser
    print("Opening scan results in your default browser...")
    webbrowser.open(f"https://www.virustotal.com/gui/file-analysis/{respjson['data']['id']}")

if __name__ == '__main__':
    main()