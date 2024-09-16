# BasicPortScanner

BasicPortScanner is a simple, multithreaded port scanning tool written in Python. It allows users to perform TCP Connect, TCP SYN, and UDP scans on specified IP addresses and port ranges.

## Features

- Multiple scan types: TCP Connect, TCP SYN, and UDP
- Customizable port range
- Multithreaded for faster scanning
- Command-line interface for easy use

## Requirements

- Python 3.x
- Scapy library

## Installation

1. Clone this repository or download the script.
2. Install the required Scapy library:

```
pip install scapy
```

## Usage

Run the script with Python, providing the necessary arguments:

```
sudo python3 scan.py [TARGET_IP] [OPTIONS]
```

### Options:

- `-p`, `--ports`: Specify the port range (default: 1-1024)
- `-s`, `--scan`: Choose the scan type (tcp_connect, tcp_syn, udp) (default: tcp_syn)
- `-t`, `--threads`: Set the number of threads to use (default: 10)

### Examples:

Scan all ports on 192.168.1.1 using TCP SYN scan:
```
sudo python3 scan.py 192.168.1.1 -p-
```

Scan ports 80-443 on 10.0.0.1 using TCP Connect scan with 20 threads:
```
sudo python3 scan.py 10.0.0.1 -p 80-443 -s tcp_connect -t 20
```