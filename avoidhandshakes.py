
#!/bin/python3

from scapy.all import *
from time import sleep
import datetime
import sys

welcome = """
       ***************
****** AVOID HANDSHAKE ******
       ***************
                              __
          ___..__       r----[__]
  __..--""  ._ __.'     *   ,'  '.
              "-..__       : ---- :
            '"--..__";     | SOAP |
 ___        '--...__"";    : ---- :
    `-..__ '"---..._;"     |  NB  |
          ' ""----'         "----"

"Always wash your hands, even after a DHCP handshake - Nicola Bottura 2020"

@Nicola Bottura,
@Giuseppe D'Agostino,
@Giorgia Lombardi.
"""

count = 0
time = []
macs = []
dict = {}


print(welcome)


def handle_dhcp(packet):
    global count, time, macs, dict

    newtime = (str(datetime.datetime.now()).split(" ")[1])
    newmac = packet.src

    if packet[DHCP].options[0][1] == 1:  # DHCP DISCOVER PACKET
        count += 1
        for time, mac in dict.items():
            if mac == newmac and count > 1:
                val = hand_washer(time, newtime, newmac)
                if val == 0:
                    sleep(60)
                    break

    dict[newtime] = newmac


def start():
    sniff(filter="udp and (port 67 or port 68)", prn=handle_dhcp, store=0)


def hand_washer(time, newtime, newmac):
    hour1 = time.split(":")[0]
    hour2 = newtime.split(":")[0]
    min1 = time.split(":")[1]
    min2 = newtime.split(":")[1]

    # If the time is the same I don't need to check the milliseconds
    # If the hour is the same but not the minutes and there are in range of 10 mins send the frame
    if (time == newtime) or ((hour1 == hour2) and (int(min2) - int(min1) in range(10))):
        send_frame(time, newtime, newmac)

        return 0
    
    else:
        return 1


def send_frame(time, newtime, newmac):
    ether = Ether()
    ether.type = 0x0101
    ether.dst = "66:a3:2e:83:1e:7f"  # Internal Router MAC
    pkt = ether/Raw(load="Warning: detected possible DHCP flooding attack by " +
                    newmac + " at" + time + "and then again at " + newtime)

    print("\nWARNING: Possible DHCP flooding attack detected!!!\n")
    print("...sending an alert to the router.\n")
    sendp(pkt, verbose=0)


try:
    while(True):
        start()

except KeyboardInterrupt:
    print("\nExiting")
    sys.exit()
