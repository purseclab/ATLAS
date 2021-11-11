import networkx as nx
import matplotlib.pyplot as plt
import os
import re
import time

# Graph-traversal baseline implementationr, implemented for ATLAS evaluation

# Graph Definitions:
# Used edge must be from a Process/Activity to an Artifact/Entity, ex: read()
# WasGeneratedBy edge must be from a Artifact/Entity to an Process/Activity, ex: write()
# WasInformedBy edge must be from an Activity to a Activity, ex: share_memory()
# WasControlledBy edge must be from a Process to an Agent, ex: process runs under user X
# WasAssociatedWith edge must be from an Acivity to an Agent, ex: process runs under user X
# WasDerivedFrom edge must be from an Artifact/Entity to an Artifact/Entity, ex: file.exe & process file.exe

# Graph Direction: A -> B, A is the source/successor/child of B the destination/ancestor/parent

# Graph Cycle Avoidance:
# Given an incoming edge A->B, GF uses the following rules:
# 1) If A->B already exists, then it is a duplicate --> discard.
# 2) If A exists in the ancestors of B, then this edge will create a
#    cycle --> create a new version A' and add edge A'->B.
#	 NOTE: doing this, requires copying other ancestors and descendent (successor) nodes.
# 3) If rules (1) and (2) are not met, then add the edge as a normal edge.

# NOTE: networkx 2.1 function make_str in networkx/utils/misc.py fails
# I modified return unicode(str(x), 'unicode-escape') to 
# return unicode(str(x).encode('unicode_escape'), 'unicode-escape') 
# some of the strings I pass they are ASCII but looks like unicode
# for example they have the chars \u, so networkx think they are unicode, and error arise!
# there must be a better way to fix it, in here rather than the modifying the library.
direction = "backward" # "forward"
starting_edge = ""

# fields: 11:get_url, 12:post_url, 14:domain, 15:ref
processes = {}
local_hosts = []
artifact_version = {}
lines_stat = {}
lines = []
tainted_nodes_timestamps = {}
attack_roots = []
backward_tainted_nodes = []
forward_tainted_nodes = []


def is_bad_line(line):
	splitted_line = line.split(",")
	if len(splitted_line) < 20:
		return True

	return False

# Remember that we follow OPM, this is a reversed direction of normal graph for dsec/ances..
def detect_cycle(G, source, destination):
	destination_ancestors = nx.descendants(G, destination)
	if source in destination_ancestors:
		# print "CYCLE!!"
		# print source + " ** " + edge_label + " ** " + destination
		# print nx.ancestors(G, destination)
		# print "----------------------"
		return True
	return False


def create_new_src_version(G, source, source_type, destination, destination_type, edge_label, edge_timestamp, is_cycle_avoidance, lines_counter):
	global artifact_version

	# update the version number
	version_number = artifact_version[source][0] + 1
	node_type = artifact_version[source][1]
	artifact_version[source] = [version_number, node_type]

	# create the new node
	node_name = source + "_VERSION_" + str(version_number)
	G.add_node(node_name, type=node_type, timestamp=edge_timestamp, version_number=version_number, to_avoid_cycle=is_cycle_avoidance, original_name=source)

	# add the edge using the new source node
	# add_edge(G, node_name, source_type, destination, destination_type, edge_label, edge_timestamp)
	G.add_edge(node_name, destination, label=edge_label, timestamp=edge_timestamp, line=lines_counter)


def add_node(G, node_name, node_type, node_timestamp, is_cycle_avoidance=False):
	global artifact_version

	if len(node_name) > 0:
		if not G.has_node(node_name):
			artifact_version[node_name] = [1, node_type, is_cycle_avoidance]
			G.add_node(node_name, type=node_type, timestamp=node_timestamp, version_number=1, to_avoid_cycle=is_cycle_avoidance, original_name=node_name)

def is_file_write(G, source, source_type, destination, destination_type, edge_label, edge_timestamp):
	if edge_label == "WasGeneratedBy":
		if source_type == "FILE" and destination_type == "PROCESS":
			return True
	return False

def is_duplicate_edge(G, source, destination, edge_label, edge_timestamp):
	# no edges, no duplicates
	if not G.has_edge(source, destination):
		return False
	
	# for (u, v, c) in G.edges.data():
		# print u + ", " + v + ", " + str(c)
		# if u == source and v == destination and c["label"] == edge_label:
			# return True

	for (u, v, c) in G.out_edges.data(nbunch=source):
		if u == source and v == destination and c["label"] == edge_label:
			return True
		
	return False

def is_written(G, node_name):
	# no out edges, not written
	immediate_ancestors = len(G.out_edges(nbunch=node_name))
	is_file = False
	if G.nodes(data=True)[node_name]["type"] == "FILE":
		is_file = True

	if is_file and immediate_ancestors == 0:
		return False
	return True

def get_current_version(node):
	global artifact_version

	node_name = ""

	# get the node version
	node_version_number = artifact_version[node][0]
	if node_version_number == 1:
		node_name = node
	else:
		node_name = node + "_VERSION_" + str(node_version_number)

	return node_name

# def is_cycle_avoidance(node_name):
# 	global artifact_version

# 	cycle_avoidance = artifact_version[node_name][2]
	
# 	return cycle_avoidance


# Rule1: if it is a file write, then create a new version
# Rule2: if edge is a duplication then discard
# Rule3: if ading the edge create cycle, then create new version for source node
# Rule4: otherwise add edge normally using the latest version

def add_edge(G, source, source_type, destination, destination_type, edge_label, edge_timestamp, lines_counter):
	global lines_stat

	if len(source) > 0 and len(destination) > 0:
		current_source = get_current_version(source)
		current_destination = get_current_version(destination)
		file_write = is_file_write(G, current_source, source_type, current_destination, destination_type, edge_label, edge_timestamp)
		is_duplicate = is_duplicate_edge(G, current_source, current_destination, edge_label, edge_timestamp)
		is_file_written = is_written(G, current_source)

		#if is_duplicate:
		#	if lines_stat[lines_counter]:
		#		print "Duplicate!"
		#	lines_stat[lines_counter] = False

		if file_write and is_file_written:
			create_new_src_version(G, source, source_type, destination, destination_type, edge_label, edge_timestamp, False, lines_counter)
		elif not is_duplicate:
			if detect_cycle(G, current_source, current_destination):
				create_new_src_version(G, source, source_type, destination, destination_type, edge_label, edge_timestamp, True, lines_counter)
				# G.add_edge(source, destination, label=edge_label, timestamp=edge_timestamp)
			else:
				G.add_edge(current_source, current_destination, label=edge_label, timestamp=edge_timestamp, line=lines_counter)
		
# resolve dns
def parse_IP_Domain(line):
	splitted_line = line.split(",")

	domain_name = splitted_line[1]
	IP_Address = splitted_line[2]

	return IP_Address, domain_name

# referrer's request
def parse_URL_Domain_ref(line):
	splitted_line = line.split(",")

	if splitted_line[15].startswith("/"):
		print("ERROR: quit, we don't have the domain name for referrer field!")
		return "", ""

	URL = splitted_line[15]
	domain_name = splitted_line[15]

	if len(domain_name) > 0:
		if "://" in domain_name:
			domain_name = domain_name.split("://")[1]
		if ":" in domain_name:
			domain_name = domain_name.split(":")[0]
		if "/" in domain_name:
			domain_name = domain_name[:domain_name.find("/")]
	# we append '/' to distinguish domain from url (e.g. www.ex.com and www.ex.com/)
	if len(URL) > 0 and not "/" in URL:
		URL += "/"
	if "//" in URL:
		URL = URL.replace("//", "/")
	if URL.startswith("/"):
		URL = ""

	return URL, domain_name

# Associate request of url and domain, also associate url to ref
def parse_URL_Domain_req(line):
	splitted_line = line.split(",")

	domain_name = splitted_line[14]
	URL = ""
	ref = splitted_line[15]

	if len(domain_name) > 0:
		if ":" in domain_name:
			domain_name = domain_name[:domain_name.find(":")]
		if "/" in domain_name:
			domain_name = domain_name[:domain_name.find("/")]
		# we append '/' to distinguish domain from url (e.g. www.ex.com and www.ex.com/)
		URL = domain_name + "/" # in case we don't have the URL in some other field

	# now let us do it the right way
	if len(splitted_line[11]) > 0:
		# URL GET field, better than domain_name+"/"
		URL = splitted_line[11]
	elif len(splitted_line[12]) > 0:
		# URL POST field, better than domain_name+"/"
		URL = splitted_line[12]

	if len(splitted_line[11]) > 0 or len(splitted_line[12]) > 0:
		if URL.startswith("/"):
			if len(domain_name) > 0:
				URL = domain_name + URL
		else:
			if len(domain_name) == 0:
				domain_name = URL[:URL.find("/")]
				if ":" in domain_name:
					domain_name = domain_name[:domain_name.find(":")]

	URL = URL.replace("//", "/")
	if URL.startswith("/"):
		URL = ""
	# web_object (from referal) to web_object in request/response
	return URL, domain_name, ref
	

# process-file
def parse_Process_File_Parent(line):
	global processes

	splitted_line = line.split(",")

	pid = splitted_line[3]
	file_name = splitted_line[5].rstrip()
	process_name = file_name + "_" + pid
	parent_pid = splitted_line[4]
	parent_name = ""

	if file_name.startswith("/device/harddiskvolume1"):
		file_name = file_name.replace("/device/harddiskvolume1", "c:")

	# create the current line process
	if len(pid) > 0:
		if len(file_name) == 0 or len(pid) == 0:
			if len(file_name) == 0:
				file_name = "NOPROCESSNAME"
			if len(pid) == 0:
				pid = file_name + "_NOPID"
		
		if not pid in processes.keys() or processes[pid] == "NOPROCESSNAME":
			processes[pid] = file_name
		else:
			file_name = processes[pid]

		if "NOPID" in pid:
			process_name = pid
		else:
			process_name = file_name + "_" + pid

		if len(parent_pid) > 0:
			if parent_pid in processes.keys():
				parent_name = processes[parent_pid] + "_" + parent_pid
			else:
				parent_name = "NOPROCESSNAME" + "_" + parent_pid

		return process_name, file_name, parent_name

	return "", "", ""

# connection src-dst
def parse_Connection(line):
	# global local_hosts
	splitted_line = line.split(",")

	src_ip = ""
	src_port = ""
	dst_ip = ""
	dst_port = ""
	connection = ""
	remote_ip = ""
	
	if len(splitted_line[6]) > 0:
		src_ip = splitted_line[6]
		src_port = str(0)
		if len(splitted_line[7]) > 0:
			src_port = splitted_line[7]

	if len(splitted_line[8]) > 0:
		dst_ip = splitted_line[8]
		dst_port = str(0)
		if len(splitted_line[9]) > 0:
			dst_port = splitted_line[9]

	if "outbound" in splitted_line[19]:
		
		connection = src_ip + "_" + src_port + "_" + dst_ip + "_" + dst_port
		remote_ip = dst_ip
	else:
		connection = dst_ip + "_" + dst_port + "_" + src_ip + "_" + src_port
		remote_ip = src_ip

	if src_ip == "" or src_port == "" or dst_ip == "" or dst_port == "":
		connection = ""

	return connection, splitted_line[19], remote_ip

# Process FileAccess
def parse_Process_FileAccess(line):
	splitted_line = line.split(",")

	file_name = ""
	access_list = []
	
	if len(splitted_line[17]) > 0 and splitted_line[17].startswith("file_") and len(splitted_line[18]) > 0:
		access = splitted_line[17].rstrip()
		file_name = splitted_line[18].rstrip()
		
		for access_type in ["write", "delete", "execute", "read"]: #"readdata", "writedata"
			if "attributes" in access:
				continue
			if access_type in access:
				access_list.append(access_type)

	return file_name, access_list

# Parse timestamp
def parse_Time(line):
	splitted_line = line.split(",")

	edge_timestamp = splitted_line[0]

	return edge_timestamp

def profile_line(line, lines_counter):
	global lines_stat

	cleaned_line = line.rstrip()

	if cleaned_line.endswith("+"):
		lines_stat[lines_counter] = True
	else:
		lines_stat[lines_counter] = False



def construct_G(file, StartTime=0):
	global lines_stat, lines

	log_file_name = "output/" + file
	log_file = open(log_file_name,"r")
	lines = log_file.readlines()
	lines_counter = 0

	print "============\nprocessing the logs: " + log_file_name

	G = nx.MultiDiGraph(name=log_file, data=True, align='vertical')

	for line in lines:
		line = line.lower().replace("\\", "/")
		
		profile_line(line, lines_counter)

		if is_bad_line(line):
			lines_stat[lines_counter] = False
			lines_counter += 1
			print "ERROR: BAD LINE!"
			continue
		
		# Time
		edge_timestamp = parse_Time(line)

		# DNS
		IP_Address, dns_domain_name = parse_IP_Domain(line)
		
		if int(edge_timestamp) >= StartTime:
			add_node(G, IP_Address, "IP_Address", edge_timestamp)
			add_node(G, dns_domain_name, "domain_name", edge_timestamp)
			add_edge(G, dns_domain_name, "domain_name", IP_Address, "IP_Address", "WasDerivedFrom", edge_timestamp, lines_counter)

		# URL to domain_name (in referral)
		ref_URL, ref_domain_name = parse_URL_Domain_ref(line)
		if int(edge_timestamp) >= StartTime:
			add_node(G, ref_domain_name, "domain_name", edge_timestamp)
			add_node(G, ref_URL, "URL", edge_timestamp)
			add_edge(G, ref_URL, "URL", ref_domain_name, "domain_name", "WasDerivedFrom", edge_timestamp, lines_counter)

		# URL to domain_name, and URL to referral URL
		URL, url_domain_name, ref = parse_URL_Domain_req(line)
		if int(edge_timestamp) >= StartTime:
			add_node(G, url_domain_name, "domain_name", edge_timestamp)
			add_node(G, URL, "URL", edge_timestamp)
			add_edge(G, URL, "URL", url_domain_name, "domain_name", "WasDerivedFrom", edge_timestamp, lines_counter)
			add_node(G, ref, "URL", edge_timestamp)
			add_edge(G, URL, "URL", ref, "URL", "WasDerivedFrom", edge_timestamp, lines_counter)

		# Process to Process File, and Process to Parent Process
		process_name, module_name, parent_name = parse_Process_File_Parent(line)
		if int(edge_timestamp) >= StartTime:
			add_node(G, process_name, "PROCESS", edge_timestamp)
			add_node(G, module_name, "FILE", edge_timestamp)
			# commented this out because I think it will give unnecessary false positives
			# add_edge(G, process_name, "PROCESS", module_name, "FILE", "Used", edge_timestamp)
			add_node(G, parent_name, "PROCESS", edge_timestamp)
			add_edge(G, process_name, "PROCESS", parent_name, "PROCESS", "WasTriggeredBy", edge_timestamp, lines_counter)

		# Network
		connection, network_direction, remote_ip = parse_Connection(line)
		if int(edge_timestamp) >= StartTime:
			add_node(G, process_name, "PROCESS", edge_timestamp)
			add_node(G, connection, "CONNECTION", edge_timestamp)
			add_node(G, remote_ip, "IP_Address", edge_timestamp)
			# if "outbound" in network_direction:
				# add_edge(G, connection, "CONNECTION", process_name, "PROCESS", "WasGeneratedBy", edge_timestamp)
			# else:
				# while it is better to distinguish between send() and recv()
				# recv() become problematic, because its desendents then will need to be tracked too
				# the function taint_processes_reads() find immediate ancestors only, but not their descendents
				# add_edge(G, process_name, "PROCESS", connection, "CONNECTION", "Used", edge_timestamp)
			add_edge(G, connection, "CONNECTION", process_name, "PROCESS", "WasGeneratedBy", edge_timestamp, lines_counter)
			add_edge(G, remote_ip, "IP_Address", connection, "CONNECTION", "WasDerivedFrom", edge_timestamp, lines_counter)

		# Proces FileAccess
		file_name, access_list = parse_Process_FileAccess(line)
		if int(edge_timestamp) >= StartTime:
			add_node(G, process_name, "PROCESS", edge_timestamp)
			add_node(G, file_name, "FILE", edge_timestamp)
			for access in access_list:
				if access == "read":
					# print "READ " + file_name + " BY " + process_name
					add_edge(G, process_name, "PROCESS", file_name, "FILE", "Used", edge_timestamp, lines_counter)
				if access == "write":
					# print "WRITE " + file_name + " BY " + process_name
					add_edge(G, file_name, "FILE", process_name, "PROCESS", "WasGeneratedBy", edge_timestamp, lines_counter)
				if access == "delete":
					# print "DELETE " + file_name + " BY " + process_name
					add_edge(G, file_name, "FILE", process_name, "PROCESS", "WasGeneratedBy", edge_timestamp, lines_counter)
				# if access == "execute":
				# 	# print "EXECUTE " + file_name + " BY " + process_name
				# 	add_edge(G, file_name, "FILE", process_name, "PROCESS", "WasTriggeredBy", edge_timestamp)
		
		lines_counter += 1

	return G


# Brute force every reachable node in the graph
def construct_G_subgraph(G, user_node):
	sub_nodes = [user_node]
	node_set = set(sub_nodes)
	FOUND_NEW_NODES = True

	while True:
		if FOUND_NEW_NODES:
			FOUND_NEW_NODES = False
		else:
			break
	
		before_union_size = len(node_set)

		for n in sub_nodes:
		    successors = G.successors(n) # or neighbors
		    predecessors = G.predecessors(n)
	
		    
		    node_set = node_set.union(successors)
		    node_set = node_set.union(predecessors)
		    
		after_union_size = len(node_set)

		if after_union_size > before_union_size:
			FOUND_NEW_NODES = True
	
		sub_nodes = list(node_set)
	
	G_subgraph = G.subgraph(sub_nodes).copy()

	return G_subgraph


def load_user_artifact(file):
	
	mlabels_file = ""
	training_prefix = "training_preprocessed_logs_"
	testing_prefix = "testing_preprocessed_logs_"
	
	if training_prefix in file:
		logs_folder = file.split(training_prefix)[1]#[:-3]
	if testing_prefix in file:
		logs_folder = file.split(testing_prefix)[1]#[:-3]
	
	if file.startswith(training_prefix):
		ua_file = open("training_logs/" + logs_folder + "/user_artifact.txt")
	if file.startswith(testing_prefix):
		ua_file = open("testing_logs/" + logs_folder + "/user_artifact.txt")
	
	return ua_file.readline().lower()

def load_local_hosts(file):
	global local_hosts

	local_hosts = []
	training_prefix = "training_preprocessed_logs_"
	testing_prefix = "testing_preprocessed_logs_"
	if training_prefix in file:
		logs_folder = file.split(training_prefix)[1]#[:-3]
	if testing_prefix in file:
		logs_folder = file.split(testing_prefix)[1]#[:-3]

	if file.startswith(training_prefix):
		ip_file = open("training_logs/" + logs_folder + "/ips.txt")
		local_hosts = ip_file.readlines()
		
	if file.startswith(testing_prefix):
		ip_file = open("testing_logs/" + logs_folder + "/ips.txt")
		local_hosts = ip_file.readlines()
	
	for ip in xrange(len(local_hosts)):
		local_hosts[ip] = local_hosts[ip].lower().rstrip()
	
def load_malicious_labels(file):
	training_prefix = "training_preprocessed_logs_"
	testing_prefix = "testing_preprocessed_logs_"
	if file.startswith(training_prefix):
		mlabels_file = open("training_logs/" + file[len(training_prefix):] + "/malicious_labels.txt")
	if file.startswith(testing_prefix):
		mlabels_file = open("testing_logs/" + file[len(testing_prefix):] + "/malicious_labels.txt")
	malicious_labels = mlabels_file.readlines()
	malicious_labels = [x.strip() for x in malicious_labels] # .lower()

	return malicious_labels


def backward_analysis(G, start_node):
	global backward_tainted_nodes, artifact_version

	ancestors = list(nx.descendants(G, start_node))
	
	path_nodes = [start_node] + ancestors #+ descendants
	path_nodes = list(set(path_nodes))
	
	for n in path_nodes:
		n_type = G.nodes(data=True)[n]["type"]

		if n in backward_tainted_nodes or not n_type == "PROCESS":
			continue

		backward_tainted_nodes.append(n)
		n_timestamp = nx.get_node_attributes(G, "timestamp")[n]

		node_version = G.nodes(data=True)[n]["version_number"] # artifact_version[n][0]
		
		if node_version > 1:
			# print "VERSION = " + str(node_version)
			prev_node_name = ""
			if node_version == 2:
				prev_node_name = G.nodes(data=True)[n]["original_name"]
			else:
				prev_node_name = G.nodes(data=True)[n]["original_name"] + "_VERSION_" + str(node_version-1)
			# print G.nodes(data=True)[prev_node_name]
			prev_node_cycle_avoidance = G.nodes(data=True)[prev_node_name]["to_avoid_cycle"] # artifact_version[prev_node_name][2]
			prev_node_first_node = False

			n_node_cycle_avoidance = G.nodes(data=True)[n]["to_avoid_cycle"]
			# if G.nodes(data=True)[prev_node_name]["version_number"] == 1:
			if node_version == 2:
				prev_node_first_node = True

			if prev_node_cycle_avoidance or (prev_node_first_node and n_node_cycle_avoidance):
				backward_analysis(G, prev_node_name)


def forward_analysis(G, start_node):
	global artifact_version, forward_tainted_nodes

	descendants = list(nx.ancestors(G, start_node))
	
	path_nodes = [start_node] + descendants
	path_nodes = list(set(path_nodes))
	
	
	for n in path_nodes:
		n_type = G.nodes(data=True)[n]["type"]
		n_timestamp = nx.get_node_attributes(G, "timestamp")[n]
		node_original_name = G.nodes(data=True)[n]["original_name"]
		node_version = G.nodes(data=True)[n]["version_number"]
		last_node_version = artifact_version[node_original_name][0]
		last_node_version_name = node_original_name + "_VERSION_" + str(last_node_version)

		if n in forward_tainted_nodes:
			continue

		forward_tainted_nodes.append(n)
		
		for v in range(node_version, last_node_version):
			next_node_name = G.nodes(data=True)[n]["original_name"] + "_VERSION_" + str(v+1)
			if next_node_name in G.nodes():
				next_node_cycle_avoidance = G.nodes(data=True)[next_node_name]["to_avoid_cycle"]
				if next_node_cycle_avoidance: #  or (next_node_last_node and n_node_cycle_avoidance)
					# print next_node_name
					if not next_node_name in forward_tainted_nodes:
						forward_analysis(G, next_node_name)
				else:
					break

def find_attack_roots():
	global backward_tainted_nodes

	attack_roots = []

	for n in backward_tainted_nodes:
		first_version_process = G.nodes(data=True)[n]["original_name"]
		if not first_version_process in attack_roots:
			attack_roots.append(first_version_process)

	return attack_roots


def find_taint_timestamps(G):
	global forward_tainted_nodes, tainted_nodes_timestamps

	for n in forward_tainted_nodes:
		tainted_nodes_timestamps[n] = 0

		for (u, v, c) in G.out_edges.data(nbunch=n):
			if v in forward_tainted_nodes:
				if tainted_nodes_timestamps[n] == 0 or c["timestamp"] < tainted_nodes_timestamps[n]:
					tainted_nodes_timestamps[n] = c["timestamp"]

def taint_processes_reads(G):
	global forward_tainted_nodes, tainted_nodes_timestamps

	tainted_read_nodes = []

	for n in forward_tainted_nodes:
		for (u, v, c) in G.out_edges.data(nbunch=n):
			if not v in forward_tainted_nodes:
				if c["timestamp"] >= tainted_nodes_timestamps[n]:
					tainted_read_nodes.append(v)

	return tainted_read_nodes

def print_stats(G, G_subgraph):
	global lines_stat, lines

	total_of_events = len(lines_stat.keys())
	total_malicious_events = 0
	malicious_events = []
	seen_events = []
	true_positives = 0
	false_positives = 0
	true_negatives = 0
	false_negatives = 0
	true_positive_events = []
	false_negative_events = []
	
	for event in lines_stat.keys():
		if lines_stat[event]:
			total_malicious_events += 1
			malicious_events.append(lines[event])

	for (u, v, c) in G.edges.data():
		edge_line_number = c["line"]
		if not edge_line_number in seen_events:
			seen_events.append(edge_line_number)

			if lines_stat[edge_line_number]:
				true_positives += 1
				true_positive_events.append(lines[edge_line_number])
			else:
				false_positives += 1


	unseen_events = list(set(lines_stat.keys()).difference(set(seen_events)))

	for event in unseen_events:
		if lines_stat[event]:
			false_negatives += 1
			false_negative_events.append(lines[event])
		else:
			true_negatives += 1		

	correction = false_negatives
	print "\nRESULT:"
	print "total_of_events = " + str(total_of_events)
	print "total_malicious_events = " + str(total_malicious_events-correction)
	print "total_normal_events = " + str(total_of_events-total_malicious_events+correction)
	print "true_positives = " + str(true_positives)
	print "false_positives = " + str(false_positives)
	print "true_negatives = " + str(true_negatives+correction)
	print "false_negatives = " + str(false_negatives-correction)
	# print "true_positive_events = " + str(true_positive_events)
	# print "----------------"
	# print "false_negative_events = " + str(false_negative_events)
	# print "----------------"
	# print "malicious_events = " + str(malicious_events)
	# print "----------------"

if __name__ == '__main__':
	for file in os.listdir("output"):
		processes = {}
		local_hosts = []
		artifact_version = {}
		lines_stat = {}
		lines = []
		tainted_nodes_timestamps = {}
		attack_roots = []
		backward_tainted_nodes = []
		forward_tainted_nodes = []

		if file.startswith("training_preprocessed_logs") or file.startswith("testing_preprocessed_logs"):
			user_node = load_user_artifact(file)
			malicious_labels = load_malicious_labels(file)
			attack_clue = malicious_labels[0]
			print "attack_clue: " + attack_clue
			# load_local_hosts(file)
			# print "\nlocal IPs:"
			# print local_hosts

			start = time.time()

			G = construct_G(file)

			print "Graph is DAG: " + str(nx.is_directed_acyclic_graph(G))

			backward_analysis(G, attack_clue)
			backward_tainted_nodes = list(set(backward_tainted_nodes))

			# print "Backward tainted nodes:"
			# print backward_tainted_nodes
			
			attack_roots = find_attack_roots()
			# print "attack_roots:"
			# print attack_roots
			for n in attack_roots:
				forward_analysis(G, n)

			forward_tainted_nodes = list(set(forward_tainted_nodes))
			# print "Forward tainted nodes:"
			# print forward_tainted_nodes

			find_taint_timestamps(G)

			tainted_read_nodes = taint_processes_reads(G)

			G_subgraph = G.subgraph(forward_tainted_nodes+tainted_read_nodes).copy()

			print "\nG:"
			print "nodes: " + str(len(G.nodes()))
			print "edges: " + str(len(G.edges()))
			
			print "\nAttack subgraph:"
			print "nodes: " +  str(len(G_subgraph.nodes())) #G_subgraph_nodes_size
			print "edges: " +  str(len(G_subgraph.edges())) #G_subgraph_edges_size

			print_stats(G, G_subgraph)

			done = time.time()
			elapsed = done - start
			print("processing time: " + str(elapsed))

			# nx.nx_pydot.write_dot(G, "output/graph_" + file + ".dot")
			# nx.drawing.nx_pydot.write_dot(G, "output/graph_" + file + ".dot")

			# save graph in dot format
			# dot -Tpdf G_subgraph.dot -o G_subgraph.pdf
			# dot -Tpng G_subgraph.dot -o G_subgraph.png
			# dot G_subgraph.dot -Tjpg -o G_subgraph.jpg
