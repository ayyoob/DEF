import csv
import subprocess
import json
import gzip

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
				cipher_suite(flow)
		except:
			pass
#		print byte_entropy_per_flow
#		quit()
		flow_counter += 1
#	print byte_entropy_per_flow
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

def cipher_suite(flow):
	if flow.has_key("tls"):
		if isinstance(flow["tls"], dict):
			if flow["tls"].has_key("cs"):
				print "yes"
				print flow["tls"]["cs"]
			else:
				return
		else:
			return
	else:
		return
	return

meta_data_extract("70:88:6b:10:0f:c6", "16-09-28.pcap")
