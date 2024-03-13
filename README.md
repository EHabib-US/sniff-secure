# sniffer-looker


Supported on: [MacOS][Linux]

Sniffs and captures packets and find objects to export (pdf files and exe files) from packets and then get the hash of it then upload to something like virustotal to see if the hash is coming from a file recognized for containing malware or not


-PyShark (pip3 install pyshark if you have wireshark already installed. If not, do so), and netifaces (pip install netifaces)