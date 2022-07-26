import socket
import argparse
from colorama import init, Fore
from threading import Thread, Lock
from queue import Queue

init()
GREEN=Fore.GREEN
RESET=Fore.RESET
GRAY=Fore.LIGHTBLACK_EX

q=Queue()
print_lock=Lock()
threads= 180

def port_scan(port):
          
          try: 
              
              s=socket.socket()
              s.connect((host,port))
              
          except:
                 with print_lock:
                       print(f"{GREEN}[!] {host:15}: {port:5} is closed {RESET}", end="\r")
          else:
               with print_lock:
                       print(f"{GRAY}[+] {host:15}: {port:5} is open {RESET}")
          finally:
                 s.close()
                 
                      
def scan_thread():
            global q
                
            while True:
                po = q.get()
                
                port_scan(po)
                
                q.task_done()
            
def main(host, port):

            global q
            
            for th in range(threads):
                           
                           th = Thread(target=scan_thread)
                           
                           th.daemon=True
                           
                           th.start()
                           
            for pt in port:
                   
                   q.put(pt)
                   
            q.join()
                   
if __name__ == "__main__":

              parser = argparse.ArgumentParser(description="port scanning tool")
              parser.add_argument("host", help="host ip address")
              parser.add_argument("--port","-p", dest="port_range", default="1-65535", help="Enter port_range, default is 1-65535")
              
              arg=parser.parse_args()
              
              host, port_range = arg.host, arg.port_range
              
              start, end = port_range.split("-")
              start, end = int(start), int(end)
              
              
              ports = [p for p in range(start, end)]
              
              
              main(host,ports)
                                     
