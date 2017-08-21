import socket

from util import ioutil
import nmap
from os import getuid, _exit
import threading
import json
import logging.config
import logging
from time import gmtime, strftime
from attacks import ATTACK_MAP
from datetime import datetime
import os
import sys
import traceback

if int(getuid()) > 0:
    print('Please run as root.')
    _exit(1)

logdatetime = strftime("%Y_%m_%d_%H_%M_%S_", gmtime())
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
        config["handlers"]["info_file_handler"]["filename"] = "logs/" + logdatetime + \
                                                              config["handlers"]["info_file_handler"]["filename"]
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


def main():
    log.info('----- IoT Device Network Exploitation Framework -----')
    hostname = socket.gethostname()
    host = socket.gethostbyname(hostname)
    netmask = ioutil.NetworkUtil.getNetMask(host)
    ipcidr = ioutil.NetworkUtil.getCidr(host, netmask)
    iprange = str(ipcidr[0].cidr)

    choice = raw_input("To scan ip range press 1 or to skip press any key: ")
    if (choice == '1'):
        choice = raw_input("enter cidr default[%s]: " % (iprange))
        if (choice != ''):
            iprange = choice

        log.info("IP Scanner started for range %s, Please Wait...." % iprange)
        nm = nmap.PortScanner()
        nm.scan(iprange, arguments='-sP -n')
        for h in nm.all_hosts():
            if 'mac' in nm[h]['addresses']:
                print(nm[h]['addresses'], nm[h]['vendor'])

    ipToAttack = raw_input("IP to attack: ")
    gateway = "192.168.0.1"
    defaultGatewayIP = raw_input("Default Gateway[%s]" % gateway)
    if (defaultGatewayIP != '') :
        gateway = defaultGatewayIP;
    log.info('IP %s is configured for the attacks', ipToAttack)
    deviceConfig = {}
    ip = {"ip": ipToAttack}
    defaultgateway = {"gateway-ip": gateway}
    macAddress = {"macAddress": ioutil.NetworkUtil.getMacbyIp(ipToAttack)}
    deviceConfig.update(ip)
    deviceConfig.update(macAddress)
    deviceConfig.update(defaultgateway)

    with open('config.json') as data_file:
        data = json.load(data_file)
    attacks = data["attack"]
    result = {}

    currentAttack = None
    try:
        for attackName in attacks:
            attackClass = classReflectionLoader(attackName)
            currentAttack = attackClass(attackName, data[attackName], deviceConfig)
            dt = datetime.now()
            attackStartTime = dt.microsecond
            log.info("%s Started." % attackName)
            attack_status = {}
            t = threading.Thread(target=currentAttack.initialize, args=(attack_status,))
            t.start()
            if (data[attackName].has_key("execution_timeout_in_seconds")) :
                t.join(data[attackName]["execution_timeout_in_seconds"])
            else:
                t.join()

            log.info("%s Result" % attack_status)
            log.info("%s Completed." % attackName)
            dt = datetime.now()
            attackCompletedTime = dt.microsecond
            currentAttack.shutdown()
            t.join()
            result.update({attackName: {"start_time": attackStartTime, "end_time": attackCompletedTime,
                              "result": attack_status}})

        deviceConfig.update({"attacks": result})
        log.info(deviceConfig)
        file = open("results/" + logdatetime + "result.json", "w")
        deviceResult = json.dumps(deviceConfig, indent=4)  # note i gave it a different name
        file.write(str(deviceResult))
        file.close()
    except Exception, j:
        log.error('Error with attack: %s, %s' % (j, traceback.format_exc()))
        if currentAttack is not None:
            currentAttack.shutdown()
        sys.exit(1)


main()