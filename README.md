# Sniffer-Looker
A Python-Based Network Security Monitoring Tool

## Overview
This tool is designed to enhance network security by monitoring, capturing, and analyzing network traffic. Utilizing the power of various Python libraries, it captures packets on a selected network adapter, extracts HTTP objects for further analysis, and finally checks the hash of these objects against the VirusTotal API for any potential security threats. This process aids in identifying potentially malicious files and activities within a network.

## Features
- Network packet capture on specified adapters.
- Exportation of HTTP objects from packet captures.
- Generation of MD5 hashes for all exported objects.
- Verification of object hashes against the VirusTotal API to identify malicious files.
- A custom progress bar to manage and display API rate limit adherence.

## Prerequisites
- **Operating Systems:** macOS, Linux
- **Dependencies:** This tool relies on these libraries and the following Python packages:
  - `pyshark` for packet capture and analysis.
  - `os`, `datetime`, `psutil`, `subprocess`, `hashlib`, `sys`, and `requests` for various system and network operations.
  - `time` for managing operation timing and API rate limits.

Please ensure that all dependencies are installed and properly configured on your system. Additionally, you _will_ need a valid VirusTotal API key to use the VirusTotal hash checking feature.

## Installation
1. Clone the repository to your local machine.
2. Install the required Python packages by running `pip install -r requirements.txt`.
3. Insert your VirusTotal API key in the script where indicated.

## Usage
To use the tool, simply run the script from the command line:

```bash
python network_security_monitor.py
