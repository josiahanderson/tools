'''
A useful script for thoroughly enumerating hosts with nmap.
by Josiah Anderson (2023)

Script steps:
1) Enumerate top 1000 ports, to quickly examine low hanging fruit.
2) Enumerate all ports on the machine.
3) Take all confirmed ports and perform a service scan.

This is the approach I used manually for the PEN-200 PWK course and exam.
The disadvantage is that the scanning is only threaded per host/scan, 
rather than per port.
'''

import nmapthon
import optparse
from threading import *

output_lock = Semaphore(value=1)


'''
Scan functions
'''
def scan_top_ports(host):
    nmap_scan = nmapthon.NmapScanner(targets=host, arguments='-Pn -T4 --top-ports 1000')
    
    try:
        nmap_scan.run()
    except Exception as e:
        print('Exception: {}'.format(e))
        
    print_scan_results(host, nmap_scan, "Top Ports Scan")
    

def scan_all_ports(host):
    nmap_scan = nmapthon.NmapScanner(targets=host, ports='1-65535', arguments='-Pn -T4')
    
    try:
        nmap_scan.run()
    except Exception as e:
        print('Exception: {}'.format(e))
    
    print_scan_results(host, nmap_scan, "All Ports Scan")
    
    scan_services(host, nmap_scan)
    
    
def scan_services(host, results):
    open_ports = build_ports_list(host, results)

    nmap_scan = nmapthon.NmapScanner(targets=host, ports=open_ports, arguments=('-Pn -A'))
    
    try:
        nmap_scan.run()
    except Exception as e:
        print('Exception: {}'.format(e))
    
    print_scan_results(host, nmap_scan, "Service Scan")



'''
Helper functions
'''  
def build_ports_list(host, results):
    open_ports = ""
    for port in results.scanned_ports(host, 'tcp'):
        open_ports = open_ports + str(port) + ','
    
    open_ports = open_ports.rstrip(',')
    
    return open_ports
    
    
def format_ports_string(host, results, protocol='tcp'):
    ports_string = ""
    for port in results.scanned_ports(host, protocol):
        state, reason = results.port_state(host, protocol, port)
        ports_string = ports_string + "\n [*] {0:<3}/{1:<9} {2}".format(protocol, port, state)
        
        service, service_info = results.standard_service_info(host, protocol, port)
        if service is not None:
            ports_string = ports_string + "\t\t({}) {}".format(service, service_info)
    
    return ports_string
    
    

'''
Print functions
'''
def print_scan_results(host, results, title):
    output_lock.acquire()
    print('============== ' + title + ' ================')
    print(results.summary)
    print('host: ' + str(results.scanned_hosts()))
    print('ports:\n-----' + format_ports_string(host, results))
    print('==============================================')
    print("\n")
    output_lock.release()
    


'''
Main function
'''
def main():
    parser = optparse.OptionParser('usage: %prog '+\
        '-H <target host>')
    parser.add_option('-H', dest='hosts', type='string', \
        help='specify target host')

    (options, args) = parser.parse_args()

    hosts = str(options.hosts).split(',')

    if (hosts[0] == None):
        print(parser.usage)
        exit(0)
    
    print('\n')
    
    for host in hosts:
        thread = Thread(target=scan_top_ports, args=[host])
        thread.start()
        
    for host in hosts:
        thread = Thread(target=scan_all_ports, args=[host])
        thread.start()
        


if __name__ == '__main__':
    main()
