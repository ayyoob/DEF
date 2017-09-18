import logging
from generic_attack import *
import logging
log = logging.getLogger(__name__)


class EntropyEstimation(GenericAttack):

    def __init__(self, attackName, attackConfig, deviceConfig):
        super(EntropyEstimation, self).__init__(attackName, attackConfig, deviceConfig)

    def initialize(self, result):
        self.running = True
        filename = 'results/' + self.device['time'] + self.device['macAddress'] + '/arp.pcap'
        # proccess pcap for entropy estimation
        log.info(filename)
	
	byte_entropy = meta_data_extract(self.config("mac_address"), filename)
	results.update({"byte_entropy": byte_entropy})



     def meta_data_extract(MAC_addr, pcap_dir):
	output = "output=" + str(MAC_addr) + ".gz"
	mac = "bpf = ether host " + str(MAC_addr)
	input = str(pcap_dir)
	subprocess.call(["bin/joy", "bidir=1", "tls=1", "dns=1", "entropy=1", "ip_id=1", "dist=1", "http=1", mac, output, input])

	f = gzip.open(output[7:],"rb")
	file = f.readlines()
	total_flows = len(file)
	flow = []
	flow_counter = 0

	byte_entropy_per_flow = []
	while flow_counter < total_flows:
		try:
			flow.append(json.loads(file[flow_counter]))
			if flow_counter != 0:
				byte_entropy_per_flow.append(byte_entropy(flow[flow_counter]))
#				cipher_suite(flow)
		except:
			pass
#		print byte_entropy_per_flow
#		quit()
		flow_counter += 1
	return byte_entropy_per_flow

    def byte_entropy(flow):
	if flow.has_key("be"):
		flow_info = {}
		flow_info["source address"] = flow["sa"]
		flow_info["destination address"] = flow["da"]
		flow_info["source port"] = flow["sp"]
		flow_info["destination port"] = flow["dp"]
		flow_info["Byte Entropy"] = flow["be"]
	else:
		return
	return flow_info

    def shutdown(self):
        self.running = False

    def prerequisite(self):
        return ["ArpSpoof"]


