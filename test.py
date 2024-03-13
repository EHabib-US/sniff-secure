import pyshark
import wmi

def get_default_wireless_adapter():
    c = wmi.WMI()
    # Query WMI for network adapters
    query = "SELECT * FROM Win32_NetworkAdapter WHERE NetConnectionID IS NOT NULL"
    adapters = c.query(query)
    
    for adapter in adapters:
        # Check if the adapter is connected and is wireless. This is a simple heuristic and might need adjustments.
        # For wireless adapters, "NetConnectionID" often contains "Wi-Fi", "Wireless", or is known to the user.
        if 'wi-fi' in adapter.NetConnectionID.lower() or 'wireless' in adapter.NetConnectionID.lower():
            # Print adapter details (optional)
            print(f"Adapter ID: {adapter.DeviceID}, Name: {adapter.Name}, Connection ID: {adapter.NetConnectionID}")
            return adapter.NetConnectionID

    return None

# Get the default wireless adapter
default_wireless_adapter = get_default_wireless_adapter()
if default_wireless_adapter:
    print(f"Default wireless adapter: {default_wireless_adapter}")
else:
    print("No default wireless adapter found.")
