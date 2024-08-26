import psutil
import nmap
from scapy.all import sniff, IP
from pysnmp.hlapi import *
import requests
import time
import socket
import warnings

# Suppress specific warnings (optional)
from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

# Function to monitor network traffic using psutil
def monitor_network():
    """Monitors network traffic using psutil."""
    print("\n--- Network Traffic Monitoring ---")
    prev_net_io = psutil.net_io_counters()
    print("Monitoring network traffic. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
            current_net_io = psutil.net_io_counters()
            sent = current_net_io.bytes_sent - prev_net_io.bytes_sent
            recv = current_net_io.bytes_recv - prev_net_io.bytes_recv
            print(f"Bytes Sent: {sent} Bytes, Bytes Received: {recv} Bytes")
            prev_net_io = current_net_io
    except KeyboardInterrupt:
        print("\nStopped monitoring.")

# Function to scan the network using nmap
def scan_network():
    """Scans the local network using nmap."""
    print("\n--- Network Scanning ---")
    nm = nmap.PortScanner()
    ip_range = input("Enter IP range to scan (e.g., 192.168.1.0/24): ")
    nm.scan(hosts=ip_range, arguments='-sn')
    for host in nm.all_hosts():
        print(f'Host: {host} ({nm[host].hostname()})')
        print(f'State: {nm[host].state()}')

# Function to capture and display network packets using scapy
def packet_sniffing():
    """Captures and displays network packets using scapy."""
    print("\n--- Packet Sniffing ---")
    interface = input("Enter the network interface to sniff on (e.g., eth0): ")

    def packet_callback(packet):
        print(packet.summary())

    print("Sniffing packets. Press Ctrl+C to stop.")
    try:
        sniff(iface=interface, prn=packet_callback)
    except KeyboardInterrupt:
        print("\nStopped sniffing.")

# Function to query an SNMP-enabled device using pysnmp
def snmp_query():
    """Queries an SNMP-enabled device using pysnmp."""
    print("\n--- SNMP Query ---")
    ip = input("Enter the IP address of the SNMP device: ")
    oid = input("Enter the OID to query (e.g., 1.3.6.1.2.1.1.1.0): ")
    iterator = getCmd(SnmpEngine(),
                      CommunityData('public', mpModel=0),
                      UdpTransportTarget((ip, 161)),
                      ContextData(),
                      ObjectType(ObjectIdentity(oid)))
    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
    if errorIndication:
        print(f"Error: {errorIndication}")
    elif errorStatus:
        print(f"Error: {errorStatus.prettyPrint()} at {errorIndex}")
    else:
        for varBind in varBinds:
            print(f'{varBind[0]} = {varBind[1]}')

# Function to monitor website traffic
def monitor_website_traffic():
    """Monitors HTTP response details for a specific website."""
    print("\n--- Website Traffic Monitoring ---")
    url = input("Enter the URL of the website (e.g., http://example.com): ")

    try:
        response = requests.get(url)
        print(f"URL: {url}")
        print(f"Status Code: {response.status_code}")
        print(f"Response Time: {response.elapsed.total_seconds()} seconds")
        print(f"Content Length: {len(response.content)} bytes")
    except requests.RequestException as e:
        print(f"An error occurred: {e}")

# Function to get the IP address of a domain
def get_ip_address(domain):
    """Gets the IP address of a domain."""
    return socket.gethostbyname(domain)

# Function to monitor traffic to a specific website using scapy
def sniff_website_traffic():
    """Sniffs packets related to a specific website."""
    print("\n--- Website Traffic Sniffing ---")
    domain = input("Enter the domain of the website to monitor (e.g., example.com): ")
    domain_ip = get_ip_address(domain)

    def packet_callback(packet):
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            if ip_dst == domain_ip:
                print(f"Source: {ip_src}, Destination: {ip_dst}")

    print(f"Monitoring traffic to {domain} ({domain_ip}). Press Ctrl+C to stop.")
    try:
        sniff(prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print("\nStopped sniffing.")

# Main function with a command-line menu for user interaction
def main():
    while True:
        print("\n--- TrafficEye Network Monitoring Tool ---")
        print("1. Monitor Network Traffic")
        print("2. Scan Network")
        print("3. Sniff Packets")
        print("4. SNMP Query")
        print("5. Monitor Website Traffic")
        print("6. Sniff Website Traffic")
        print("7. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            monitor_network()
        elif choice == '2':
            scan_network()
        elif choice == '3':
            packet_sniffing()
        elif choice == '4':
            snmp_query()
        elif choice == '5':
            monitor_website_traffic()
        elif choice == '6':
            sniff_website_traffic()
        elif choice == '7':
            print("Exiting TrafficEye...")
            break
        else:
            print("Invalid choice. Please try again.")

# Entry point of the script
if __name__ == "__main__":
    main()
