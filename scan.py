"""
DISCLAIMER: This code is intended for educational purposes only. The author does not condone or support any illegal or unethical activities, including unauthorized access to computer systems. The user of this code is solely responsible for its use. By using this code, you agree to use it responsibly and in compliance with all applicable laws and regulations.
"""
from scapy.all import *

ip = "172.168.0.1"
#ports list is made of ports that are assumed to be running services which means that anyone
#attempting to connect to a different port is potentially malicious and will be listed in blocked
ports=[53,80] 
honeyports =[8080,8443]

blocked = []

def analyzePacekts(p):
  global blocked
  if p.haslayer(IP):
    response= Ether(src=p[Ether].dst,dst=p[Ether].src) /\ IP(src=p[IP].dst,dst=p[IP].src) /\ TCP (sport=p[TCP].dport,dport=p[TCP].sport,ack=p[TCP].seq+1)
    source = p[IP].src
  else:
    response= Ether(src=p[Ether].dst,dst=p[Ether].src) /\ IPv6(src=p[IPv6].dst,dst=p[IPv6].src) /\ TCP (sport=p[TCP].dport,dport=p[TCP].sport,ack=p[TCP].seq+1)
    source = p[IPv6].src
  if p[TCP].flags != "S":
    return
  port = p[TCP].dport 
  if source in blocked:
    if port in ports:
      response[TCP].flags = "RA"
      print ("Sending reset")
    elif port in honeyports:
      reponse[TCP].flags = "SA"
    else:
      return
    sendp(response, verbose=False)
  else:
    if port not in ports:
      blocked += [source]
      if port in honeports:
        response[TCP].flags = "SA"
        sendp(respone, verbose=False)

f = "dst host "+ip+" and tcp"
sniff(filter=f, prn=analyzePackets)
