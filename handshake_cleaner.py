from scapy.all import *
from time import sleep
import datetime

f=open("output.txt", "w+")
count = 0
time = []
macs = []

def handle_dhcp(packet):
	global count

	if packet[DHCP].options[0][1]==1:
		f.write(packet.src + '\n')
		time.pop(datetime.datetime.now())
		count+=1

	if count%3 == 0: #se ho 3 elementi nuovi
		hand_washer(time, macs)

	f.write("#" + str(count) + ": " + str(time) + "\n")
	sleep(1)

def cicle():
	sniff(filter="port 67 and port 68", prn=handle_dhcp, store=0, iface='eth0')

def hand_washer(time, macs):
	last=len(time)

	if (time[last] - time[last-1] - time[last-2]) <= 0.5: #controlla anche il mac
		#troppe richieste dallo stesso MAC in troppo poco tempo

try:
	cicle()

except KeyboardInterrupt:
	sys.exit()
