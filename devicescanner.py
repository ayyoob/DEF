import socket

from util import ioutil
import nmap
from os import getuid, _exit
import os
import json
import logging.config
import logging
from attacks import generic_attack
from attacks import ATTACK_MAP

if int(getuid()) > 0:
    print('Please run as root.')
    _exit(1)

def setup_logging(default_path='logging.json', default_level=logging.INFO,env_key='LOG_CFG'):
    """Setup logging configuration
     """
    path = default_path
    value = os.getenv(env_key, None)
    if value:
        path = value
    if os.path.exists(path):
        with open(path, 'rt') as f:
            config = json.load(f)
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
                attackMap.update({ module: ATTACK_MAP[module]})


setup_logging()
log = logging.getLogger(__name__)
loader = LoadedModules()
attackMap = {}
loader.load(attackMap)

log.info('----- IoT Device Network Exploitation Framework -----')

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

    log.info("IP Scanner started for range %s, Please Wait...." % iprange)
    nm = nmap.PortScanner()
    nm.scan(iprange, arguments='-sP -n')
    for h in nm.all_hosts():
        if 'mac' in nm[h]['addresses']:
            print(nm[h]['addresses'], nm[h]['vendor'])

ipToAttack = raw_input("IP to attack: ")
log.info('IP %s is configured for the attacks', ipToAttack)
deviceConfig = {}
ip = {"ip": ipToAttack}
macAddress = {"macAddress": ioutil.NetworkUtil.getMacbyIp(ipToAttack)}
deviceConfig.update(ip)
deviceConfig.update(macAddress)

with open('config.json') as data_file:
    data = json.load(data_file)
attacks = data["attack"]

for attackName in attacks:
    attackClass = classReflectionLoader(attackName)
    currentAttack = attackClass(attackName, data[attackName], deviceConfig)
    currentAttack.initialize()
    currentAttack.shutdown()





