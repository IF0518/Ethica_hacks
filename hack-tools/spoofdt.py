from scapy.all import ARP, srp, sniff, Ether, conf

def get_mac(ip):
              
              packet= Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip)
              result=srp(packet,verbose=false, timeout=3)[0]
              return result[0][1].hwsrc
                        
def process(packet):
                    
        if packet.haslayer(ARP):
                       
                       if packet[ARP].op == 2: 
                                 try:
                                      real_mac = get_mac(packet[ARP].psrc)
                                      
                                      reply_mac = packet[ARP].hwsrc
                                      
                                      if real_mac != reply_mac:
                                                    print(f"Your are under attack: Real-mac: {real_mac.upper()}, fake mac: {Reply-mac.upper()}")
                                                    
                                 except IndexError:
                                                    pass
                                  
                                      
                                                    

if __name__ == "__main__":
                       
                       import sys
                       try:
                           
                           iface = sys.argv[1]
                           
                       except IndexError:
                            
                            iface= conf.iface
                            
                       sniff(store=False, prn=process, iface=iface)                            
                                    
                                    
                                    
                                            
