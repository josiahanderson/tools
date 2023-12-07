"""
Josiah Anderson
A simple TCP connect port scanner.
Derived from: "Violent Python, A Cookbook for Hackers" by TJ O'Connor
"""

import optparse
from socket import *
from threading import *

output_lock = Semaphore(value=1)

def connect_scan(host, port):
    try:
        sock = socket(AF_INET, SOCK_STREAM)
        sock.connect((host, port))
        sock.send(b'darkstar\r\n')

        results = sock.recv(100)
        output_lock.acquire()

        print(' [+] %d/tcp open' % port)
        print(' [>] Banner: ' + str(results))

    except:
        output_lock.acquire()
        print(' [-] %d/tcp closed' % port)

    finally:
        output_lock.release()
        sock.close()


def port_scan(host, ports):
    try:
        ip = gethostbyname(host)
    except:
        print(" [-] Cannot resolve '%s': Unknown host" % host)
        return

    try:
        hostname = gethostbyaddr(ip)
        print('\n [+] Scan results for: ' + hostname[0])
    except:
        print('\n [+] Scan results for: ' + ip)

    setdefaulttimeout(1)
    for port in ports:
        thread = Thread(target=connect_scan, args=(host, int(port)))
        thread.start()


def main():
    parser = optparse.OptionParser('usage: %prog '+\
        '-H <target host> -p <target port>')
    parser.add_option('-H', dest='host', type='string', \
        help='specify target host[s] separated by comma')
    parser.add_option('-p', dest='port', type='string', \
        help='specify target port[s] separated by comma')

    (options, args) = parser.parse_args()

    hosts = str(options.host).split(',')
    ports = str(options.port).split(',')

    if (hosts[0] == None) | (ports[0] == None):
        print(parser.usage)
        exit(0)

    for host in hosts:
        port_scan(host, ports) 


if __name__ == "__main__":
    main()
