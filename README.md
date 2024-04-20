# ARP Watcher

## Overview
This application provides a graphical user interface for monitoring ARP traffic on a network to detect new and changed MAC addresses associated with IP addresses. It is built using the PyQt5 library and utilizes the Scapy library to sniff network packets.

## Features
- Real-time ARP traffic monitoring.
- Detection of new and changed MAC addresses.
- GUI display of IP addresses, MAC addresses, and their status (new or changed).
- Ability to start and stop monitoring.

## Requirements
- Python 3.x
- PyQt5
- Scapy

## Installation
First, ensure you have Python installed on your system. You can download it from [python.org](https://www.python.org/downloads/).

Next, install the required Python libraries using pip:
```bash
pip install PyQt5 scapy
```

## Usage
To run the ARP Sniffer GUI, navigate to the directory containing the script and run:
```python main.py```
