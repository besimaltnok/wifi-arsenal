from scapy.all import *

iface    = 'wlan0mon'
maclist  = []
ssidlist = []
def ClientTracker(pkt):
	if pkt.haslayer(Dot11ProbeReq):
		ssid = pkt.info
		mac  = pkt.addr2
		if mac not in maclist and len(ssid) != 0:
			maclist.append(mac)
			ssidlist.append(ssid)
			print("%s Send Probe Request to %s AP" %(mac, ssid))
		else:
			if ssid not in ssidlist and len(ssid) != 0:
				ssidlist.append(ssid)
				print("%s Send Probe Request to %s AP" %(mac, ssid))


if __name__ == '__main__':
	os.system('reset')
	print("---------Client Tacker----------")
	sniff(iface=iface, count=0, prn=ClientTracker)
