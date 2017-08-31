import logging
from generic_attack import *
import logging
log = logging.getLogger(__name__)


class PasswordAttack(GenericAttack):

    def __init__(self, attackName, attackConfig, deviceConfig):
        super(PasswordAttack, self).__init__(attackName, attackConfig, deviceConfig)

    def initialize(self, result):
        self.running = True
        target = self.device['ip']

        if self.device["vulnerable_ports"] is None:
            result.update({"status": "no open ports"})
            return

        if "tcp" not in self.device["vulnerable_ports"].keys():
            result.update({"status": "no open ports"})
            return

        if "open" not in self.device["vulnerable_ports"]["tcp"].keys():
            result.update({"status": "no open ports"})
            return
        
        openPorts = self.device["vulnerable_ports"]["tcp"]["open"]
        # telnet and ssh tests needs to be added here


    def shutdown(self):
        self.running = False

    def prerequisite(self):
        return ["PortVulnerabilityTest"]
