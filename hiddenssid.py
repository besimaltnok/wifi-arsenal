#!/usr/bin/env python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import argparse

hiddenlist = []
detectedlist = []
helpme = """
Author : Besim ALTINOK ||| Team: CyberPath Training
"""

parser = argparse.ArgumentParser(description=helpme)
parser.add_argument('-i', action='store', dest='iface',
                    help='Interface name (Monitor mode)\n') 
args = parser.parse_args()

iface  = args.iface


def DetectHiddenSSID(pkt):
	if pkt.haslayer(Dot11Beacon):
		if "\x00" in str(pkt.info) or "" in str(pkt.info):
			if pkt.addr2 not in hiddenlist:
				hiddenlist.append(pkt.addr2)

def FindHiddenSSID(pkt):
	if pkt.haslayer(Dot11ProbeResp) and pkt.addr2 in hiddenlist:
		if pkt.addr2 not in detectedlist:
			detectedlist.append(pkt.addr2)
			print(" Hidden SSID Broadcast Detected : \n") 
			print("  * MAC Address : ", pkt.addr2)
			print("  * SSID info   : ", pkt.info)
			print("---------------------------------\n")
	elif pkt.haslayer(Dot11ProbeResp):
		print(pkt.info, pkt.addr2)

if __name__ == '__main__':
	os.system('reset')
	print("[+] We are working for detect hidden SSID Broadcast ...")
	sniff(iface=iface, timeout=30, prn=DetectHiddenSSID)
	if len(hiddenlist) == 0:
		print("[*] We can not detect any broadcast SSID")
		exit
	else:
		print("[+] DETECTED %d HIDDEN ACCESS POINT" %(len(hiddenlist)))
		print("[+] We are working DETECTION ...")
		sniff(iface=iface, count=0, prn=FindHiddenSSID)
