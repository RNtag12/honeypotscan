
# Active Scanning with Honeypot Integration
This project implements advanced active scanning techniques using the Scapy library in Python. It integrates SYN scan detection with honeypot functionality to identify and respond to unauthorized access attempts on specified ports.

# General Information
Network reconnaissance can be performed using either active or passive methods. Active reconnaissance involves direct interaction with the target environment, such as performing port or vulnerability scans. Passive reconnaissance, on the other hand, may involve eavesdropping on traffic or using publicly available information sources.

MITRE ATT&CK's Active Scanning technique is an example of active reconnaissance. It includes performing scans to determine active IP addresses, running services, existing vulnerabilities, and other relevant intelligence.

Scapy Library
Scapy is a powerful Python library used for crafting, sending, and receiving network packets. It is particularly useful for network scanning, tracerouting, probing, and other network-related tasks. The official home of Scapy is https://scapy.net.

Project Description
This project aims to implement SYN scan detection and honeypot responses using the Scapy library in Python. The SYN scan detection monitors specified ports for SYN packets, which are indicative of port scanning attempts. The honeypot functionality responds to these scans, either resetting the connection for protected ports or acknowledging it for honeypot ports. This project demonstrates how to use Scapy to perform advanced network monitoring and active defense tasks.

Features
SYN Scan Detection: Monitors specified TCP ports for SYN packets, indicative of scanning attempts.

Honeypot Integration: Responds to unauthorized access attempts with specific actions, such as resetting the connection or acknowledging the attempt.

Customizable Port Lists: Allows specification of protected ports and honeypot ports.

Interactive Input: Accepts target IP address and ports list input from the user.

Error Handling: Validates IP address and ports input, handling invalid entries gracefully.

Interactions in the Code
The code defines three lists of ports: ports for protected ports, honeys for honeypot ports, and blocked for sources that have attempted to access unauthorized ports. The analyzePackets function processes incoming packets to determine if they are SYN scans. Depending on the source and destination ports, it sends appropriate responses to either reset the connection or acknowledge the attempt.

python
Copy code
from scapy.all import *

ip = "172.26.32.1"
ports = [53, 80]
honeys = [8080, 8443]
blocked = []

def analyzePackets(p):
    global blocked
    if p.haslayer(IP):
        response = Ether(src=p[Ether].dst, dst=p[Ether].src) / \
                   IP(src=p[IP].dst, dst=p[IP].src) / \
                   TCP(sport=p[TCP].dport, dport=p[TCP].sport, ack=p[TCP].seq + 1)
        source = p[IP].src
    else:
        response = Ether(src=p[Ether].dst, dst=p[Ether].src) / \
                   IPv6(src=p[IPv6].dst, dst=p[IPv6].src) / \
                   TCP(sport=p[TCP].dport, dport=p[TCP].sport, ack=p[TCP].seq + 1)
        source = p[IPv6].src

    if p[TCP].flags != "S":
        return
    
    port = p[TCP].dport

    if source in blocked:
        if port in ports:
            response[TCP].flags = "RA"
            print("Sending reset")
        elif port in honeys:
            response[TCP].flags = "SA"
        else:
            return
        sendp(response, verbose=False)
    else:
        if port not in ports:
            blocked.append(source)
        if port in honeys:
            response[TCP].flags = "SA"
            sendp(response, verbose=False)

f = "dst host " + ip + " and tcp"
sniff(filter=f, prn=analyzePackets)
Steps to Execute the Project
Prepare the Environment: Ensure Python and Scapy are installed on your system.
Create the Script:
Copy the provided code into a Python script file (e.g., HoneypotScan.py).
Run the Script:
Execute the script using the command python HoneypotScan.py.
Monitor the Output:
The script will display logs of SYN scan detections and honeypot interactions.
Conclusion
By following these steps, you can use this project to implement SYN scan detection and honeypot responses on your network, enhancing your understanding of network security and active defense mechanisms.
