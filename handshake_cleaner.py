
#!/bin/python3

from scapy.all import *
from time import sleep
import datetime
import sys

count = 0
time = []
macs = []

def handle_dhcp(packet):
	global count, time, macs
	if packet[DHCP].options[0][1] == 1: #DHCP DISCOVER PACKET
		macs += [packet.src]
		time += [(str(datetime.datetime.now()).split(" ")[1])]
		count+=1

	if macs[count-1] == macs[count-2] and count>1: #quando ricevo un secondo pacchetto con la stessa src del primo
		hand_washer(time, macs, count)

def start():
	sniff(filter="port 67 and port 68", prn=handle_dhcp, store=0, iface='eth0')

def hand_washer(time, macs, count):
	t1 = time[count-1].split(".") # HH:MM:SS, MILLISEC - For the last pkt
	t2 = time[count-2].split(".") # "  "  "  "  "  "   - For the penultimate pkt
	min1 = int(t1[0].split(":")[1]) # Just minutes
	min2 = int(t2[0].split(":")[1]) # "  "  "  "  

	'''
		Controllo se il formato hh:mm:ss sono uguali oppure
		se la differenza dei minuti tra il primo e secondo pacchetto
		e' minore o uguale a 10(minuti).
	'''
	if (t1[0] == t2[0]) or ((min2 - min1) in range(10)): 
		send_frame(macs[count-1])

	print("My job here is done...exiting\n")
	print("...but you didn't do anything\n")

	sys.exit()

def send_frame(MAC):
	ether = Ether()
	ether.type = 0x0101
	ether.dst = "66:a3:2e:83:1e:7f" # Internal Router MAC
	pkt = ether/Raw(load = "Warning: detected possible DHCP flooding attack by " + MAC)

	print("\nWARNING: Possible DHCP flooding attack detected!!!\n")
	print("...sending an alert to the router.\n")
	sendp(pkt, verbose=0)

try:
	start()

except KeyboardInterrupt:
	sys.exit()
