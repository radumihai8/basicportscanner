from queue import Queue
from scapy.all import *
import argparse

# Suppress Scapy warnings
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


def tcp_connect_scan(target, port):
    """
    Perform a TCP Connect scan on a specific port.

    This function attempts to establish a full TCP connection to the target port.
    It's the most basic form of TCP scanning, but also the most detectable.

    Args:
        target (str): The IP address of the target.
        port (int): The port number to scan.

    Returns:
        bool: True if the port is open, False otherwise.
    """
    try:
        # Create a new socket object
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Set a timeout of 1 second
        sock.settimeout(1)
        # Attempt to connect to the target IP and port
        result = sock.connect_ex((target, port))
        # Close the socket to free up resources
        sock.close()
        # If result is 0, connection was successful (port is open)
        return result == 0
    except:
        return False


def tcp_syn_scan(target, port):
    """
    Perform a TCP SYN scan on a specific port.

    This function sends a SYN packet to the target port and analyzes the response.
    It's faster and less noisy than a full TCP connect scan.

    Args:
        target (str): The IP address of the target.
        port (int): The port number to scan.

    Returns:
        bool: True if the port is open, False otherwise.
    """
    try:
        # Generate a random source port for our packet
        srcport = RandShort()
        # Disable verbose output from Scapy
        conf.verb = 0
        # Send a SYN packet and wait for a response
        SYNACKpkt = sr1(IP(dst=target) / TCP(sport=srcport, dport=port, flags="S"), timeout=1)
        # If we received a packet back
        if SYNACKpkt is not None:
            # Get the TCP flags from the response
            pktflags = SYNACKpkt.getlayer(TCP).flags
            # Check if the flags are SYN-ACK (0x12)
            if pktflags == 0x12:
                return True  # Port is open
        return False  # Port is closed or filtered
    except Exception as e:
        print(f"An error occurred during SYN scan on port {port}: {e}")
        return False


def udp_scan(target, port):
    """
    Perform a UDP scan on a specific port.

    This function sends an empty UDP packet to the target port and checks for a response.
    UDP scans are generally less reliable than TCP scans.

    Args:
        target (str): The IP address of the target.
        port (int): The port number to scan.

    Returns:
        bool: True if the port is open, False otherwise.
    """
    try:
        # Create a new UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Set a timeout of 1 second
        sock.settimeout(1)
        # Send an empty packet to the target port
        result = sock.sendto(b'', (target, port))
        # Wait for a response
        data, addr = sock.recvfrom(1024)
        # Close the socket
        sock.close()
        # If we get here, we received a response (port is likely open)
        return True
    except socket.error:
        # If we get a socket error, assume the port is closed or filtered
        return False


def worker(target, scan_type):
    """
    Worker function for multithreaded scanning.

    This function is the target for each thread, performing the actual port scanning.
    It continuously pulls ports from the queue and scans them until the queue is empty.

    Args:
        target (str): The IP address of the target.
        scan_type (str): The type of scan to perform ('tcp_connect', 'tcp_syn', or 'udp').
    """
    while not queue.empty():
        # Get a port number from the queue
        port = queue.get()
        # Perform the appropriate scan based on the scan_type
        if scan_type == 'tcp_connect':
            result = tcp_connect_scan(target, port)
        elif scan_type == 'tcp_syn':
            result = tcp_syn_scan(target, port)
        elif scan_type == 'udp':
            result = udp_scan(target, port)
        else:
            print(f"Invalid scan type: {scan_type}")
            return

        # If the port is open, print it and add to the list
        if result:
            print(f"Port {port} is open")
            open_ports.append(port)
        # Mark this task as done in the queue. Queue.join will wait until all tasks are marked as done.
        queue.task_done()


if __name__ == "__main__":
    # Set up command-line argument parsing
    parser = argparse.ArgumentParser(description="Port Scanner")
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("-p", "--ports", default="1-1024", help="Port range to scan (default: 1-1024)")
    parser.add_argument("-s", "--scan", choices=['tcp_connect', 'tcp_syn', 'udp'], default='tcp_syn',
                        help="Scan type (default: tcp_syn)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads to use (default: 10)")
    args = parser.parse_args()

    # Extract arguments
    scan_target = args.target
    scan_type = args.scan
    threads = args.threads

    # Determine port range
    if args.ports == "-":
        start_port, end_port = 1, 65535  # Scan all ports
    else:
        start_port, end_port = map(int, args.ports.split('-'))
    ports = range(start_port, end_port + 1)

    # Initialize queue and results list
    queue = Queue()
    open_ports = []

    # Fill queue with ports to scan
    for _port in ports:
        queue.put(_port)

    # Create and start threads
    thread_list = []
    for t in range(threads):
        thread = threading.Thread(target=worker, args=(scan_target, scan_type))
        thread_list.append(thread)
        thread.start()

    # Wait for all threads to complete
    for thread in thread_list:
        thread.join()

    print("Open ports are:", open_ports)
