from scapy.all import *
import sys

# Complete this function!
def process_pcap(pcap_fname):
    mydicS ={}
    mydicSA ={}
    for pkt in PcapReader(pcap_fname):
        
        # Your code here
        a = raw(pkt)
        t =Ether(a)

        if(IP in t and TCP in t):

            if(t[TCP].flags == "S"):
                if(t[IP].src in mydicS):

                    mydicS[t[IP].src] += 1
                else:
                    mydicS[t[IP].src] = 1
                #print("S",mydicS)

            if(t[IP].dst in mydicS and t[TCP].flags =="SA"):

                if(t[IP].dst in mydicSA):
                    mydicSA[t[IP].dst] += 1
                else:
                    mydicSA[t[IP].dst] = 1
                #print("SA", mydicSA)
            
        #print(t.show())

    for ip in mydicS:
        if (ip not in mydicSA):
            print(ip)
        if (ip in mydicSA):
            if ((mydicS.get(ip) / mydicSA.get(ip) >= 3)):
                print(ip)
    pass


if __name__=='__main__':
    if len(sys.argv) != 2:
        print('Use: python3 detector.py file.pcap')
        sys.exit(-1)
    process_pcap(sys.argv[1])