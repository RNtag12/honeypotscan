
# Active Scanning with Honeypot Integration
This project implements active scanning  using the Scapy library in Python. It integrates SYN scan detection with honeypot functionality to identify and respond to unauthorized access attempts on specified ports.

# Project Description
This project aims to implement SYN scan detection and honeypot responses using the Scapy library in Python. The SYN scan detection monitors specified ports for SYN packets, which are indicative of port scanning attempts. The honeypot functionality responds to these scans, either resetting the connection for protected ports or acknowledging it for honeypot ports. This project demonstrates how to use Scapy to perform advanced network monitoring and active defense tasks.
# Features
- <b>SYN Scan Detection: </b> Monitors specified TCP ports for SYN packets, indicative of scanning attempts.
- <b>Honeypot Integration: </b> Responds to unauthorized access attempts with specific actions, such as resetting the connection or acknowledging the attempt.
- <b>Customizable Port Lists: </b>Allows specification of protected ports and honeypot ports.
- <b>Interactive Input: </b>Accepts target IP address and ports list input from the user.
- <b>Error Handling: </b>Validates IP address and ports input, handling invalid entries gracefully.

# Interactions in the Code
The code defines three lists of ports: ports for protected ports, honeys for honeypot ports, and blocked for sources that have attempted to access unauthorized ports. 
The analyzePackets function processes incoming packets to determine if they are SYN scans. Depending on the source and destination ports, it sends appropriate responses to either reset the connection or acknowledge the attempt.

# Conclusion
By following these steps, you can use this project to implement SYN scan detection and honeypot responses on your network, enhancing your understanding of network security and active defense mechanisms.
