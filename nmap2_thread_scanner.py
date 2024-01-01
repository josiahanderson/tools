'''
A useful script for thoroughly enumerating hosts with nmap.
by Josiah Anderson (2023)

Script steps:
1) Enumerate top 1000 ports, to quickly examine low hanging fruit.
2) Enumerate all ports on the machine.
3) Take all confirmed ports and perform a service scan.

This is the approach I used manually for the PEN-200 PWK course and exam.

This version uses the improved nmapthon2 library and makes better use of
threading and asynchronous scanning.
'''

import nmapthon2
import optparse
from threading import *
from nmapthon2.ports import tcp, udp, top_ports

output_lock = Semaphore(value=1)


'''
Scan functions
'''
def scan_top_ports(host):
    try:
        nmap_scan = nmapthon2.NmapAsyncScanner()
        nmap_scan.scan(host, ports=top_ports(1000), arguments='-Pn -T4')
        
        nmap_scan.wait()    
        print_scan_results(nmap_scan.get_result(), "Top Ports Scan")
    except Exception as e:
        print('Exception: {}'.format(e))
    

def scan_all_ports(host):
    try:
        nmap_scan = nmapthon2.NmapAsyncScanner()
        nmap_scan.scan(host, ports='1-65535', arguments='-Pn -T4')
        
        nmap_scan.wait()    
        print_scan_results(nmap_scan.get_result(), "All Ports Scan")
    
        scan_services(host, nmap_scan.get_result())
    except Exception as e:
        print('Exception: {}'.format(e))
    
    
def scan_services(host, results):
    open_ports = build_ports_list(host, results)

    try:
        nmap_scan = nmapthon2.NmapAsyncScanner()
        nmap_scan.scan(host, ports=open_ports, arguments='-Pn -A')
        
        nmap_scan.wait()
        print_scan_results(nmap_scan.get_result(), "Service Scan")
    except Exception as e:
        print('Exception: {}'.format(e))



'''
Helper functions
'''  
def build_ports_list(host, results):
    open_ports = ""
    for scanned_host in results:
        if scanned_host is host:
            for port in ports:
                open_ports = open_ports + str(port) + ','
    
    return open_ports.rstrip(',')
    
    
def format_ports_string(results):
    ports_string = ""
    for host in results:
        ports_string = ports_string + "\nhost: {} - {}\nports:\n-----".format(host.hostnames(), host.ipv4)
        for port in host:
            ports_string = ports_string + "\n [*] {0:<3}/{1:<9} {2}".format(port.protocol, port.number, port.state)
        
            service = port.service
            if service is not None:
                ports_string = ports_string + "\t\t({}) {} {} {}".format( \
                    convert_none(service.name), \
                    convert_none(service.product), \
                    convert_none(service.version), \
                    convert_none(service.extrainfo))
    
    return ports_string


def convert_none(value):
    if value is not None:
        return value
    else:
        return ''
    

'''
Print functions
'''
def print_scan_results(results, title):
    output_lock.acquire()
    print('============== ' + title + ' ================')
    print(results.summary)
    print(format_ports_string(results))
    print('==============================================')
    print('\n')
    output_lock.release()
    


'''
Main function
'''
def main():
    parser = optparse.OptionParser('usage: %prog ' + \
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
