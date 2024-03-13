import pyshark
import wmi
import os
import datetime

#Creates a new folder to output packet captures
def create_capture_folder(base_dir="captures"): #/captures
    if not os.path.exists(base_dir):
        os.makedirs(base_dir)
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    folder_path = os.path.join(base_dir, f"capture_{timestamp}") #creates string of path for the new capture_Y/m/d/H/M/S directory to base directory /captures
    os.makedirs(folder_path) #creates directory from folder_path string
    return folder_path

#Display network adapters via WMI Query, save into dictionary for fast selection, then select until right one is chosen
def get_default_wireless_adapter():
    c = wmi.WMI()
    query = "SELECT * FROM Win32_NetworkAdapter WHERE NetConnectionID IS NOT NULL"
    adapters = c.query(query)
    adapter_map = {adapter.NetConnectionID: adapter.Name for adapter in adapters} #Create a dictionary to map Connection IDs to adapter names for quick lookup
    for connection_id, name in adapter_map.items():
        print(f"Name: {name}\nConnection ID: {connection_id}\n")
    while True:
        selected_adapter_id = input("Begin by choosing your adapter above by its Connection ID: ")
        if selected_adapter_id in adapter_map:
            return selected_adapter_id
        print("Invalid selection, please try again.")

#Sniff and capture packets then save to new directory in /captures/
def sniffer(selected_adapter):
    folder_path = create_capture_folder()
    file_path = os.path.join(folder_path, "captured_packets.pcap")
    capture = pyshark.LiveCapture(interface=selected_adapter, output_file=file_path)
    capture.sniff(timeout=1)
    print(f"Packets saved to {os.getcwd()}\{file_path}")

#Export Objects from Pcap



# Example usage
selected_adapter = get_default_wireless_adapter()
if selected_adapter:
    sniffer(selected_adapter)
else:
    print("No adapter selected.")
