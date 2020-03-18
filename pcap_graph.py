#!/usr/bin/python

import pyshark
import sys, os.path
import matplotlib.pyplot as plt
#from matplotlib.externals import six
import numpy as np
from matplotlib.ticker import FuncFormatter

#global variable
win=1

def analyze_pcap(pcap):
	print ()
	
# returns ip or ipv6
def find_src_ip(pkt):
	if hasattr(pkt, 'ip'):
		#print(pkt.ip.src)
		return pkt.ip.src
	elif hasattr(pkt, 'ipv6'):
		#print(pkt.ipv6.src)
		return pkt.ipv6.src
	else:
		#print("no ip")
		return None

def find_dst_ip(pkt):
	if hasattr(pkt, 'ip'):
		#print(pkt.ip.dst)
		return pkt.ip.dst
	elif hasattr(pkt, 'ipv6'):
		#print(pkt.ipv6.dst)
		return pkt.ipv6.dst
	else:
		#print("no ip")
		return None

def find_src_mac(pkt):
	if hasattr(pkt, 'eth'):
		#print(pkt.eth.src)
		return pkt.eth.src
	else:
		#print("no mac")
		return None

def find_dst_mac(pkt):
	if hasattr(pkt, 'eth'):
		#print(pkt.eth.dst)
		return pkt.eth.dst
	else:
		#print("no mac")
		return None
		
def find_transport_protocol(pkt):
	if hasattr(pkt, 'transport_layer'):
		protocol =  pkt.transport_layer
		return protocol
	return None

def find_transport_src_port(pkt):
	protocol =  find_transport_protocol(pkt)
	if protocol != None:
		return pkt[pkt.transport_layer].srcport
	else:
		return None
		
def find_transport_dst_port(pkt):
	protocol =  find_transport_protocol(pkt)
	if protocol != None:
		return pkt[pkt.transport_layer].dstport
	else:
		return None

def find_tcp_port(pkt):
	if hasattr(pkt, 'tcp'):
		print(pkt.tcp.port)
		return pkt.tcp.port
	else:
		print("not tcp")
		return "not tcp"

def find_udp_port(pkt):
	if hasattr(pkt, 'udp'):
		print(pkt.udp.port)
		return pkt.udp.port
	else:
		print("not udp")
		return "not udp"

def find_udp_src_port(pkt):
	if hasattr(pkt, 'udp'):
		print(pkt.udp.srcport)
		return pkt.udp.srcport
	else:
		print("not udp")
		return "not udp"

def find_udp_dst_port(pkt):
	if hasattr(pkt, 'udp'):
		print(pkt.udp.dstport)
		return pkt.udp.dstport
	else:
		print("not udp")
		return "not udp"
		
def find_DSCP(pkt):
	if hasattr(pkt, 'tcp'):
		if hasattr(pkt.ip, 'dsfield_dscp'):
			print(pkt.ip.dsfield_dscp)
			return pkt.ip.dsfield_dscp
		else:
			print("not dsfield_dscp")
			return "not dsfield_dscp"
	else:
		print("not ip")
		return "not ip"

def find_ttl(pkt):
	if hasattr(pkt, 'ip'):
		print(pkt.ip.ttl)
		return pkt.ip.ttl
	else:
		print("not ip")
		return "not ip"

def exit():
	sys.exit()
	
def detect_ftp_attack(pkt):
	global ftp_pkt_list
	try:
		if pkt.tcp.srcport == "50021" or pkt.tcp.dstport == "50021":
			if pkt.ip.src == target_ip or pkt.ip.dst == target_ip:
				ftp_pkt_list.append(pkt)
	except:
		pass

def print_conversation_header(pkt):
    try:
        protocol =  pkt.transport_layer
        src_addr = pkt.ip.src
        src_port = pkt[pkt.transport_layer].srcport
        dst_addr = pkt.ip.dst
        dst_port = pkt[pkt.transport_layer].dstport
        Data = pkt.data.data.decode('hex')
		#Data=pkt.data.data.decode('hex')
        print ('%s  %s:%s --> %s:%s' % (protocol, src_addr, src_port, dst_addr, dst_port))
        print (Data)

    except AttributeError as e:
        #ignore packets that aren't TCP/UDP or IPv4
        pass

def length_graph(pkt_list):
	global win
	length=[]
	pkt=[]
	avg_len=[]
	i=1	
	total_len=0
	try:

		for p in pkt_list:
			l = int(p.length)
			total_len= l + total_len
			length.append(l)
			pkt.append(i)
			i=i+1
	except AttributeError as e:
		pass
	avg = total_len / (i - 1)
	for j in range(1, i):
		avg_len.append(avg)
	
	g=plt.figure(win)
	win = win + 1

	# plotting the points 
	plt.plot(pkt, avg_len, label='average length', color='r')
	#print (length)
	#print (pkt)
	plt.plot(pkt, length, label='actual length', marker='.')
	
	# naming the x axis
	plt.xlabel('Packets')
	# naming the y axis
	plt.ylabel('Length (bytes)')
	
	plt.title('Length-Packet graph')
	# show a legend on the plot
	plt.legend(loc='upper left', bbox_to_anchor=(0.6, 1.05),
          ncol=3, fancybox=True, shadow=True)
	g.show()
	#raw_input()

def val_to_percent(y, position):
    # Ignore the passed in position. This has the effect of scaling the default
    # tick locations.
    s = str(y)
    return s + '%'
	
def length_hist(len_list):
	global win
	fig, ax1 = plt.subplots()
	n_groups = 5
	index = np.arange(n_groups)
	bar_width = 0.35

	opacity = 0.4
	error_config = {'ecolor': '0.3'}

	len_range=('0-100', '100-500', '500-1000', '1000-1500', '1500<')
	rects1 = ax1.bar(index + bar_width, len_list, bar_width,
                 alpha=opacity,
                 color='b', 
                 error_kw=error_config
                 )
				 
	ax1.set_xlabel('No. of Packets')
	ax1.set_ylabel('Length (bytes)')
	plt.title('Length-Packet bar graph')
	plt.xticks(index + bar_width + bar_width/2, len_range)

	per=[]
	
	total=float(sum(len_list))
	#print (total)
	for i in len_list:
		per.append(percentage(float(i),total))
		
	ax2 = ax1.twinx()
	ax2.plot(index + bar_width + bar_width/2, per, '*r-')
	formatter = FuncFormatter(val_to_percent)
	ax2.set_ylabel('Percentage', color='r')
	ax2.tick_params('y', colors='r')
	plt.gca().yaxis.set_major_formatter(formatter)
	fig.tight_layout()
	plt.show()
	
def summary_table(list1,list2,list3,list4,list5,list6,list7, list8, list9, list10):
	global win
	t=plt.figure(win)
	win = win + 1
	rows=('Source IP','Destination IP','Src Port','Dst Port','Protocol','Src MAC','Dst MAC','TTL','IP FLAGS', 'TCP FLAGS')
	cols=['Details']

	cell_text=[[list_as_string(list1)],[list_as_string(list2)],[list_as_string(list3)],
		[list_as_string(list4)],[list_as_string(list5)],[list_as_string(list6)],[list_as_string(list7)],
		[list_as_string(list8)],[list_as_string(list9)], [list_as_string(list10)]]
	
	#plt.table(cellText=[list_as_string(list1),'f','z','g','g','q','f'],
	the_table = plt.table(cellText=cell_text,
                      rowLabels=rows,
                      colLabels=cols,
					  cellLoc='left',
					  colLoc='center',
                      loc='upper center',bbox=(-0.05, 0, 1.14, 1))
	#plt.subplots_adjust(left=0.2, bottom=0.3)
	#for k, cell in six.iteritems(the_table._cells):
		#cell.set_edgecolor(edge_color)
        #if k[0] == 0 or k[1] < header_columns:
	#	cell.set_text_props( color='b', wrap=True)
            #cell.set_facecolor(header_color)
	#the_table._cells.set_text_props(weight='bold', color='w', wrap=True)
	
	cells = [key for key in the_table._cells ]
	for cell in cells:
		#print key[1]
		#print the_table._cells[cell].PAD
		the_table._cells[cell].PAD = 0.05
	
	#the_table.scale(1.3, 4)
	the_table.auto_set_font_size(False)
	the_table.set_fontsize(9)
	#print  the_table.properties()
	#table_props = the_table.properties()
	#table_cells = table_props['child_artists']
	#for cell in table_cells: print cell
	plt.axis('off')
	t.show()


def list_as_string(list):
	str = ', '.join(list)
	return str

def append_unique(list, value):
	if list.count(value) == 0:
		list.append(value)
	return list
	
def percentage(n, total):
	return (n * 100) / total
###########################Main script

if(len(sys.argv) < 2) :
	print ('Usage : python intruder.py pcap-filename camera-ip')
	file = input('Enter a pcap filename: ')
	if file == '\n':
		exit()
	target_ip = input('Enter the camera IP: ')
	if target_ip == '\n':
		exit()
else:
	file = sys.argv[1]
	target_ip = sys.argv[2]

if not os.path.isfile(file):
	print (file,"Error: file not found")
	exit()

#target_ip = raw_input('Enter the camera IP: ')
packet_list=[]
src_ip_list=[]
dst_ip_list=[]
src_port_list=[]
dst_port_list=[]
protocol_list=[]
src_mac_list=[]
dst_mac_list=[]
ftp_pkt_list=[]
tcp_flags=[]
ip_flags=[]
ttl_list=[]
length=[0,0,0,0,0] #

try:		
	cap = pyshark.FileCapture(file, keep_packets=False)
	print ("Analyzing packets...")
	
	#cap.apply_on_packets(detect_ftp_attack)
	if len(ftp_pkt_list) > 0:
		print ("FTP attack detected")
		for pkt in ftp_pkt_list:
			print_conversation_header(pkt)
	
	#cap.apply_on_packets(print_conversation_header)

	for pkt in cap:
		#neglect eth layer packet
		if not hasattr(pkt, 'ip'):
			continue
		src_ip=find_src_ip(pkt)
		dst_ip=find_dst_ip(pkt)
		if src_ip == target_ip or dst_ip == target_ip:
			packet_list.append(pkt)
			ttl_list = append_unique(ttl_list, pkt.ip.ttl)
			src_ip_list = append_unique(src_ip_list, src_ip)
			dst_ip_list = append_unique(dst_ip_list, dst_ip)
			src_mac=find_src_mac(pkt)
			if src_mac != None:
				src_mac_list = append_unique(src_mac_list, src_mac)
			dst_mac=find_dst_mac(pkt)
			if dst_mac != None:
				dst_mac_list = append_unique(dst_mac_list, dst_mac)
			protocol = find_transport_protocol(pkt)
			if protocol != None:
				protocol_list = append_unique(protocol_list, protocol )
				src_port = find_transport_src_port(pkt)
				src_port_list = append_unique(src_port_list, src_port)
				dst_port = find_transport_dst_port(pkt)
				dst_port_list = append_unique(dst_port_list, dst_port)
			else:
				protocol_list = append_unique(protocol_list, pkt.highest_layer)
			#find IP flags
			if pkt.ip.flags_rb == '1':
				ip_flags = append_unique(ip_flags, 'Reserved bit')
			if pkt.ip.flags_mf == '1':
				ip_flags = append_unique(ip_flags, 'More fragments')
			if pkt.ip.flags_df == '1':
				ip_flags = append_unique(ip_flags, 'Don\'t fragment')
			#find tcp flags
			if hasattr(pkt, 'tcp'):
				if pkt.tcp.flags_fin == '1':
					tcp_flags = append_unique(tcp_flags, 'FIN')
				if pkt.tcp.flags_syn == '1':
					tcp_flags = append_unique(tcp_flags, 'SYN')
				if pkt.tcp.flags_reset == '1':
					tcp_flags = append_unique(tcp_flags, 'RESET')
				if pkt.tcp.flags_push == '1':
					tcp_flags = append_unique(tcp_flags, 'PSH')
				if pkt.tcp.flags_ack == '1':
					tcp_flags = append_unique(tcp_flags, 'ACK')
				if pkt.tcp.flags_urg == '1':
					tcp_flags = append_unique(tcp_flags, 'URG')
				if pkt.tcp.flags_ecn == '1':
					tcp_flags = append_unique(tcp_flags, 'ECN')
				if pkt.tcp.flags_cwr == '1':
					tcp_flags = append_unique(tcp_flags, 'CWR')
				if pkt.tcp.flags_ns == '1':
					tcp_flags = append_unique(tcp_flags, 'NS')
				if pkt.tcp.flags_res != '0':
					tcp_flags = append_unique(tcp_flags, 'RES')
			l= int(pkt.length)
			if l <= 100:
				length[0] += 1
			elif l <= 500:
				length[1] += 1
			elif l <= 1000:
				length[2] += 1
			elif l <= 1500:
				length[3] += 1
			elif l > 1500:
				length[4] += 1
		################
		'''if pkt.ip.src == target_ip or pkt.ip.dst == target_ip:
		protocol =  pkt.transport_layer
		print(protocol)
		src_addr = pkt.ip.src
		src_port = pkt[pkt.transport_layer].srcport
		dst_addr = pkt.ip.dst
		dst_port = pkt[pkt.transport_layer].dstport
		if pkt.ip.src == target_ip or pkt.ip.dst == target_ip:
			if src_mac_list.count(pkt.eth.src) == 0:
				src_mac_list.append(pkt.eth.src)
			if dst_mac_list.count(pkt.eth.dst) == 0:
				dst_mac_list.append(pkt.eth.dst)
			if protocol_list.count(protocol) == 0:
				protocol_list.append(protocol)
			if dst_port_list.count(dst_port) == 0:
				dst_port_list.append(dst_port)
			if src_port_list.count(src_port) == 0:
				src_port_list.append(src_port)
			packet_list.append(pkt)
			if dst_ip_list.count(pkt.ip.dst) == 0:
				dst_ip_list.append(pkt.ip.dst)
			if src_ip_list.count(pkt.ip.src) == 0:
				src_ip_list.append(pkt.ip.src)'''

	
		'''elif pkt.ip.dst == target_ip:
			if src_mac_list.count(pkt.eth.src) == 0:
				src_mac_list.append(pkt.eth.src)
			if dst_mac_list.count(pkt.eth.dst) == 0:
				dst_mac_list.append(pkt.eth.dst)
			if protocol_list.count(protocol) == 0:
				protocol_list.append(protocol)
			if dst_port_list.count(dst_port) == 0:
				dst_port_list.append(dst_port)
			if src_port_list.count(src_port) == 0:
				src_port_list.append(src_port)
			packet_list.append(pkt)
			if src_ip_list.count(pkt.ip.src) == 0:
				src_ip_list.append(pkt.ip.src)'''
	input=len(packet_list)
	if input == 0:
		print ("no packet detected with Src or Dst IP as target_ip:",target_ip)
		exit()
	print('Total packets detected with either Src or Dst IP as target_ip:',input)
	#print (list_as_string(src_ip_list))#, src_port_list, protocol_list)
	summary_table(src_ip_list, dst_ip_list, src_port_list, dst_port_list,
		protocol_list,src_mac_list,dst_mac_list, ttl_list, ip_flags, tcp_flags)
	length_graph(packet_list)
	length_hist(length)
	
	#print('press Enter to exit!')
	#raw_input()
	'''#commented
	while input != "0":
		print ("0) Quit")
		print ("1) Print packets summary")
		print ("2) Print list of unique source IPs")
		print ("3) Print list of unique destination IPs")
		print ("4) Print list of unique source MACs")
		print ("5) Print list of unique destination MACs")
		
		input=raw_input('Enter a choice (index): ')
		if input == "1":
			#select=raw_input('a) All b) index: ')
			for pkt in packet_list:
				print (pkt)
				
		elif input == "2":
			for ip in src_ip_list:
				print (ip)
		elif input == "3":
			for ip in dst_ip_list:
				print (ip)
		elif input == "4":
			for ip in src_mac_list:
				print (ip)
		elif input == "5":
			for ip in dst_mac_list:
				print (ip)
		elif input == "0":
			print ("bye bye")
		else:
			print ("Wrong input!!!")
			'''
except:
	print("Some Exception",e)
