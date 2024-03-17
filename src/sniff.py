import pyshark
import os
import datetime
import psutil
import subprocess
import hashlib
import sys
import requests
import time

#INSERT API KEY HERE
api_key = "INSERT_API_KEY_HERE"

def check_hashes_against_virustotal(hash_file_path):
    session = requests.Session()
    session.headers = {'x-apikey': api_key}

    with open(hash_file_path, 'r') as file:
        hashes = [line.split()[1].strip() for line in file.readlines()]

    for hash_str in hashes:
        url = f"https://www.virustotal.com/api/v3/files/{hash_str}"
        response = session.get(url)
        if response.status_code == 200:
            result = response.json()
            detections = sum(1 for analysis in result.get('data', {}).get('attributes', {}).get('last_analysis_results', {}).values() if analysis.get('category') == 'malicious')
            total_engines = len(result.get('data', {}).get('attributes', {}).get('last_analysis_results', {}))
            print(f"Hash: {hash_str} - Detections: {detections}/{total_engines}")
            if detections > 0:
                print("Potentially Malicious")
            else:
                print("Not Malicious")
        else:
            print(f"Hash: {hash_str} - VirusTotal does not have data on this hash or the API call failed.")

        # Wait to prevent hitting the API rate limit
        progressbar()
        

def progressbar(duration=15, width=40):
    sys.stdout.write("Waiting to prevent API rate limit exceedance\n[{}]".format(" " * width))
    sys.stdout.flush()
    sys.stdout.write("\b" * (width + 1))  # return to start of line, after '['

    for i in range(width):
        time.sleep(duration / width)  # Adjust sleep time as needed
        sys.stdout.write("-")
        sys.stdout.flush()

    sys.stdout.write("]\n")  # ends the progress bar
    

#Creates a new folder to output packet captures
def create_capture_folder(base_dir="captures"):
    if not os.path.exists(base_dir):
        os.makedirs(base_dir)
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    folder_path = os.path.join(base_dir, f"capture_{timestamp}")
    os.makedirs(folder_path)
    return folder_path

#Display network adapters via psutil, save into dictionary for fast selection, then select until right one is chosen
def choose_adapter():
    addrs = psutil.net_if_addrs()
    for adapter in addrs:
        print(adapter)
    while True:
        response = input("Type in your adapter from above: ")
        if response in addrs:
            return response
        print("\nInvalid option, please type again")

#Gets latest capture folder
def get_latest_capture_folder(base_dir="captures"):
    folders = [os.path.join(base_dir, d) for d in os.listdir(base_dir) if os.path.isdir(os.path.join(base_dir, d))]
    latest_folder = max(folders, key=os.path.getmtime)
    return latest_folder

#Sniff and capture packets then save to new directory in /captures/
def sniffer(selected_adapter):
    folder_path = create_capture_folder()
    file_path = os.path.join(folder_path, "captured_packets.pcap")
    timeout_length = 5
    print(f"Starting packet capture on {selected_adapter}. This will last {timeout_length} seconds.")
    capture = pyshark.LiveCapture(interface=selected_adapter, output_file=file_path)
    capture.sniff(timeout=timeout_length)
    print(f"Packets saved to {file_path}")
    return file_path

#Export HTTP Objects from a PCAP file
def export_http_objects_from_pcap(pcap_file, export_dir):
    if not os.path.exists(export_dir):
        os.makedirs(export_dir)

    tshark_command = [
        "tshark",
        "-Q",
        "--export-objects", f"http,{export_dir}",
        "-r", pcap_file
    ]

    result = subprocess.run(tshark_command, capture_output=True, text=True)

    # Check if the directory is not empty and if the command was successful
    if result.returncode == 0 and len(os.listdir(export_dir)) > 0:
        print(f"HTTP objects exported successfully to {export_dir}.")
    else:
        if result.returncode != 0:
            print("Failed to export HTTP objects.")
            print(result.stderr)
        else:
            print("No HTTP objects were found to export. Please continue to stay safe!")
        
        
#Gets hash of all files in the exported http objects folder and outputs into a txt file line by line for each file
def hash_exported_http_objects(export_dir):
    hash_file_path = os.path.join(export_dir, "exported_objects_hashes.txt")
    with open(hash_file_path, 'w') as hash_file:
        for filename in os.listdir(export_dir):
            file_path = os.path.join(export_dir, filename)
            #avoid infinite hashing on itself
            if file_path == hash_file_path:
                continue
            with open(file_path, 'rb') as f:
                file_content = f.read()
                file_hash = hashlib.md5(file_content).hexdigest()
                hash_file.write(f"{filename}: {file_hash}\n")
    print(f"MD5 hashes of exported objects saved to {hash_file_path}")


#CHANGE ANYTHING BELOW THIS:
def progressbar():
    toolbar_width = 40
    sys.stdout.write("[%s]" % (" " * toolbar_width))
    sys.stdout.flush()
    sys.stdout.write("\b" * (toolbar_width+1))  # return to start of line, after '['
    for i in range(toolbar_width):
        time.sleep(0.5)  # Adjust sleep time as needed
        sys.stdout.write("-")
        sys.stdout.flush()
    sys.stdout.write("]\n")  # this ends the progress bar

def check_hashes_against_virustotal(hash_file_path):
    with open(hash_file_path, 'r') as file:
        hashes = file.readlines()

    for hash_line in hashes:
        hash_str = hash_line.split()[1]
        response = requests.get(
            f'https://www.virustotal.com/vtapi/v2/file/report',
            params={'apikey': api_key, 'resource': hash_str}
        ).json()

        # Simple output, expand based on the information you need
        if response.get('response_code') == 1:
            positives = response.get('positives', 0)
            total = response.get('total', 0)
            print(f"Hash: {hash_str} - Positives: {positives}/{total}")
            if positives > 0:
                print("Malicious")
            else:
                print("Not Malicious")
        else:
            print(f"Hash: {hash_str} - VirusTotal does not have data on this hash.")

        progressbar()  # Wait to prevent hitting the API rate limit

#Main
if __name__ == "__main__":
    #Choose network adapter
    selected_adapter = choose_adapter()

    #Start packet capture and get the file path of the captured packets
    pcap_file_path = sniffer(selected_adapter)

    #Get the latest capture folder
    latest_folder = get_latest_capture_folder()
    export_directory = os.path.join(latest_folder, "exported_http_objects")
    print(f"Exporting HTTP objects to: {export_directory}")

    #Export HTTP Objects from the captured pcap file
    export_http_objects_from_pcap(pcap_file_path, export_directory)

    #Generate hash of all exported objects and write to a txt file
    hash_file_path = os.path.join(export_directory, "exported_objects_hashes.txt")
    hash_exported_http_objects(export_directory)

    #Upload hash to VirusTotal and check if the file the hash derives from is malicious or not
    check_hashes_against_virustotal(hash_file_path)
