import socket
from netaddr import *

from util import ioutil
print("----- IoT Device Network Exploitation Framework -----")
import nmap

hostname = socket.gethostname()
host = socket.gethostbyname(hostname)
netmask = ioutil.NetworkUtil.getNetMask(host)
ipcidr = ioutil.NetworkUtil.getCidr(host, netmask)
iprange = str(ipcidr[0].cidr)

choice = raw_input("To scan ip range press 1 or to skip press any key: ")

if (choice == '1'):
    choice = raw_input("enter cidr default[%s]: " % (iprange))
    if (choice != '') :
        iprange = choice

    print("IP Scanner started for range %s, Please Wait...." % iprange)
    nm = nmap.PortScanner()
    nm.scan(iprange, arguments='-T5 -O')
    for h in nm.all_hosts():
        if 'mac' in nm[h]['addresses']:
            print(nm[h]['addresses'], nm[h]['vendor'])

choice = raw_input("IP to attack: ")




