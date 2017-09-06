import socket

from util import ioutil
from util import report_generator
from lib import nmap_python
from os import getuid, _exit
import threading
import json
import logging.config
import logging
from time import gmtime, strftime
from attacks import ATTACK_MAP
import os
import sys
import traceback
import netifaces
import time

if int(getuid()) > 0:
    print('Please run as root.')
    _exit(1)

logdatetime = strftime("%Y_%m_%d_%H_%M_%S", gmtime())
def setup_logging(default_path='logging.json', default_level=logging.INFO, env_key='LOG_CFG'):
    """Setup logging configuration
     """
    path = default_path
    value = os.getenv(env_key, None)
    if value:
        path = value
    if os.path.exists(path):
        with open(path, 'rt') as f:
            config = json.load(f)
        try:
            os.makedirs('./results/' + logdatetime)
        except OSError:
            pass
        config["handlers"]["info_file_handler"]["filename"] = "results/" + logdatetime + "/" + config["handlers"]["info_file_handler"]["filename"]
        logging.config.dictConfig(config)
    else:
        logging.basicConfig(level=default_level)


def classReflectionLoader(name):
    name = 'attacks.%s.%s' % (ATTACK_MAP[name], name)
    components = name.split('.')
    mod = __import__(components[0])
    for comp in components[1:]:
        mod = getattr(mod, comp)
    return mod

def blockPrint():
    sys.stdout = open(os.devnull, 'w')

class LoadedModules:
    """ Load modules
    """

    def __init__(self):
        self.attacks = {}

    def load(self, attackMap):
        """ Load modules.  Verify the module loads successfully
            before loading it up into the module list; this prevents
            crashes related to unmet dependencies.
        """
        for module in ATTACK_MAP.keys():
            if ioutil.NetworkUtil.check_dependency('attacks.%s' % ATTACK_MAP[module]):
                attackMap.update({module: ATTACK_MAP[module]})


setup_logging()
log = logging.getLogger(__name__)
attackMap = {}
loader = LoadedModules()
loader.load(attackMap)

def validatePrerequisite(data):
    attacks = data["attack"]
    for attackName in attacks:
        attackClass = classReflectionLoader(attackName)
        currentAttack = attackClass(None, None, None)
        prerequisiteAttacks = currentAttack.prerequisite()
        if prerequisiteAttacks is None:
            continue
        attackIndex = attacks.index(attackName)
        attacksSet = set(attacks[:attackIndex])
        status = set(prerequisiteAttacks).issubset(attacksSet)
        if not status:
            return False, ''.join(prerequisiteAttacks)

    return True, "success"


def performAttacks(data, deviceConfig, iprange):
    result = {}
    attacks = data["attack"]
    interval = data["interval_between_attacks_in_seconds"]
    currentAttack = None
    macAddress = deviceConfig['macAddress']
    try:
        for attackName in attacks:

            ipToAttack = getIp(iprange, macAddress)
            retryCount = 0
            maxRetry = 5
            while (ipToAttack is None or ipToAttack == '') and retryCount < maxRetry:
                ipToAttack = getIp(iprange, macAddress)
                retryCount = retryCount + 1
                time.sleep(5)
                log.info("Device with macAddress %s is not reachable, retrying" % macAddress)
            if ((ipToAttack is None or ipToAttack == '') and retryCount == maxRetry):
                log.info("Device with macAddress %s is not reachable" % macAddress)
                sys.exit(1)

            deviceConfig['ip'] = ipToAttack
            attackClass = classReflectionLoader(attackName)
            currentAttack = attackClass(attackName, data[attackName], deviceConfig)
            attackStartTime = int(time.time())
            log.info("%s Started. for device ip %s " % (attackName, ipToAttack))
            attack_status = {}
            t = threading.Thread(target=currentAttack.initialize, args=(attack_status,))
            t.start()

            if (data[attackName].has_key("execution_timeout_in_seconds")):
                t.join(data[attackName]["execution_timeout_in_seconds"])
            else:
                t.join()
            currentAttack.shutdown()
            t.join()
            log.info("%s Result" % attack_status)
            log.info("%s Completed." % attackName)
            attackCompletedTime = int(time.time())
            result.update({attackName: {"start_time": attackStartTime, "end_time": attackCompletedTime,
                                        "result": attack_status}})
            time.sleep(interval)

        return result;
    except Exception, j:
        log.error('Error with attack: %s, %s' % (j, traceback.format_exc()))
        if currentAttack is not None:
            currentAttack.shutdown()
        return result;

def getIp(iprange, macAddress):
    nm = nmap_python.PortScanner()
    nm.scan(iprange, arguments='-sP -n')
    for h in nm.all_hosts():
        if 'mac' in nm[h]['addresses']:
            if nm[h]['addresses']['mac'] == macAddress:
                return nm[h]['addresses']['ipv4']

    return None

def getDeviceNetworkConfig(data):
    interfaces = data["interfaces"]
    interfaces = interfaces.split(',')
    hostname = socket.gethostname()
    host = socket.gethostbyname(hostname)
    netmaskIsSet = False
    netmask = ''
    broadcast_ip = ''
    for interface in interfaces:
        try:
            host = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']
            netmask = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['netmask']
            broadcast_ip = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['broadcast']
            netmaskIsSet = True
        except Exception, j:
            pass
    if not netmaskIsSet:
        host = socket.gethostbyname(hostname)
        netmask = ioutil.NetworkUtil.getNetMask(host)

    ipcidr = ioutil.NetworkUtil.getCidr(host, netmask)
    iprange = str(ipcidr[0].cidr)

    macAddress = data['mac_address']
    if macAddress is None or macAddress == "":
        choice = raw_input("To scan ip range press 1 or to skip press any key: ")
        if (choice == '1'):
            choice = raw_input("enter cidr default[%s]: " % (iprange))
            if (choice != ''):
                iprange = choice

            log.info("IP Scanner started for range %s, Please Wait...." % iprange)
            nm = nmap_python.PortScanner()
            nm.scan(iprange, arguments='-sP -n')
            for h in nm.all_hosts():
                if 'mac' in nm[h]['addresses']:
                    print(nm[h]['addresses'], nm[h]['vendor'])
        macAddressToAttack = ''
        while macAddressToAttack == '':
            macAddressToAttack = raw_input("MacAddress to attack: ")
        gateway = netifaces.gateways()['default'].values()[0][0]
        defaultGatewayIP = raw_input("Default Gateway[%s]" % gateway)
        if (defaultGatewayIP != ''):
            gateway = defaultGatewayIP;
        macAddress = macAddressToAttack
    else:
        defaultGateway = data['default_gateway']
        if defaultGateway is None or defaultGateway == "":
            gateway = netifaces.gateways()['default'].values()[0][0]
        else:
            gateway = defaultGateway

    return macAddress, gateway, broadcast_ip, iprange

def main():
    log.info('----- IoT Device Network Exploitation Framework -----')
    with open('config.json') as data_file:
        data = json.load(data_file)

    status, invalidAttack = validatePrerequisite(data)
    if not status:
        log.error("%s prerequisite is not configured" % invalidAttack)
        return False;

    macAddress, gateway, broadcast_ip, iprange = getDeviceNetworkConfig(data);
    if data['blockPrint']:
        blockPrint()
    ipToAttack = getIp(iprange, macAddress)
    if ipToAttack is None:
        log.info("device not available for %s " % macAddress)
        return
    log.info('IP %s & macAddress %s is configured for the attacks' % (ipToAttack, macAddress))
    deviceConfig = {}
    defaultgateway = {"gateway-ip": gateway}
    macAddress = {"macAddress": macAddress}
    broadcast = {"broadcast_ip": broadcast_ip}
    testTimeStamp = {"time": logdatetime}
    ip = {"ip": ipToAttack}

    deviceConfig.update(ip)
    deviceConfig.update(macAddress)
    deviceConfig.update(defaultgateway)
    deviceConfig.update(broadcast)
    deviceConfig.update(testTimeStamp)


    result = performAttacks(data, deviceConfig, iprange)

    deviceConfig.update({"attacks": result})
    deviceConfig.update({"setup": data})
    log.info(deviceConfig)
    file = open("results/" + logdatetime + "/result.json", "w")
    deviceResult = json.dumps(deviceConfig, indent=4)
    file.write(str(deviceResult))
    file.close()

    reportGenerator = report_generator.ReportGenerator(data, deviceConfig, result)
    reportGenerator.generate()

main()