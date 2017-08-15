from __future__ import print_function
from netaddr import *
import subprocess

class NetworkUtil:
    @staticmethod
    def getFirstIp(ipAddress, subnet):
        ipBin = IPNetwork(ipAddress).ip.bits().split('.')
        subBin = IPNetwork(subnet).ip.bits().split('.')
        zipped = zip(ipBin, subBin)
        netIdList = []
        for octets in zipped:
            netIdList.append(''.join(
                str(b) for b in (map((lambda x: int(x[0]) * int(x[1])), zip(list(octets[0]), list(octets[1]))))))
        firstIp = ''
        firstIp = '.'.join(str(int(oct, 2)) for oct in netIdList)
        return firstIp

    @staticmethod
    def getLastIp(ipAddress, subnet):
        ipBin = IPNetwork(ipAddress).ip.bits().split('.')
        subBin = IPNetwork(subnet).ip.bits().split('.')
        # print ipBin
        # print subBin
        revsubBin = []
        for octets in subBin:
            revB = ''.join('1' if (b == '0') else '0' for b in octets)
            revsubBin.append(revB)
        zipped = zip(ipBin, revsubBin)
        netIdList = []
        for octets in zipped:
            netIdList.append(''.join(str(b) for b in (
            map((lambda x: 0 if (int(x[0]) == 0 and int(x[1]) == 0) else 1), zip(list(octets[0]), list(octets[1]))))))
        # print netIdList
        lastIp = ''
        lastIp = '.'.join(str(int(oct, 2)) for oct in netIdList)
        return lastIp

    @staticmethod
    def getRangeOfIps(firstIp, lastIp):
        start = int(IPAddress(firstIp))
        end = int(IPAddress(lastIp))
        ipList = []
        for ip in range(start, end + 1):
            ipList.append(str(IPAddress(ip)))
        return ipList

    @staticmethod
    def manipulateIP(ipAddress, subnet):
        firstIp = NetworkUtil.getFirstIp(ipAddress, subnet)
        lastIp = NetworkUtil.getLastIp(ipAddress, subnet)
        ipList = NetworkUtil.getRangeOfIps(firstIp, lastIp)
        return ipList

    @staticmethod
    def hex_to_ip_decimal(hex_data):
        ipaddr = "%i.%i.%i.%i" % (
        int(hex_data[0:2], 16), int(hex_data[2:4], 16), int(hex_data[4:6], 16), int(hex_data[6:8], 16))
        return ipaddr

    @staticmethod
    def getCidr(ipAddress, subnet):
        firstIp = NetworkUtil.getFirstIp(ipAddress, subnet)
        lastIp = NetworkUtil.getLastIp(ipAddress, subnet)
        return iprange_to_cidrs(firstIp, lastIp)

    @staticmethod
    def getNetMask(ip):
        proc = subprocess.Popen('ifconfig', stdout=subprocess.PIPE)
        while True:
            line = proc.stdout.readline()
            if ip in line:
                netmask = line.strip().split(' ')[3][2:]
                return NetworkUtil.hex_to_ip_decimal(netmask)
            elif line is None:
                break
        return None