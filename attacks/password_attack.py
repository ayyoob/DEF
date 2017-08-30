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
            return {"status": "no_open_ports"}
        elif self.device["vulnerable_ports"]["tcp"] is None:
            return {"status": "no_open_ports"}
        elif self.device["vulnerable_ports"]["tcp"]["open"] is None:
            return {"status": "no_open_ports"}

        openPorts = self.device["vulnerable_ports"]["tcp"]["open"]
        # telnet and ssh tests needs to be added here


    def shutdown(self):
        self.running = False


