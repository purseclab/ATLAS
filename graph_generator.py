import networkx as nx
import matplotlib.pyplot as plt
import os
import re
import time

# NOTE: networkx 2.1 function make_str in networkx/utils/misc.py fails
# I modified return unicode(str(x), 'unicode-escape') to 
# return unicode(str(x).encode('unicode_escape'), 'unicode-escape') 
# some of the strings I pass they are ASCII but looks like unicode
# for example they have the chars \u, so networkx think they are unicode, and error arise!
# there must be a better way to fix it, in here rather than the modifying the library.

log_file_name = ""
user_node = 'C:/Users/aalsahee/Desktop/payload.exe'.lower()
ROOT = None
sub_nodes = [user_node]
node_set = set(sub_nodes)
ROOT_G_subgraph = None
ROOT_sub_nodes = []
abstractd_leaf_nodes = []
sub_nodes_leaf_nodes = []
sub_abstractd_leaf_nodes = sub_nodes_leaf_nodes
node_set_leaf_nodes = set(sub_nodes_leaf_nodes)
log_file = None
lines = []

#G = nx.MultiDiGraph(name=log_file, data=True, align='vertical')
G = None
G_subgraph = None
processes = {}
sub_root_nodes = [user_node]
node_set = set(sub_root_nodes)
found_roots = []
total_nodes_in_sets = ""
hosts_ips = []

def construct_G(IncludeExecutedEdges=True, StartTime=0):
	global lines, G

	G = nx.MultiDiGraph(name=log_file, data=True, align='vertical')

	for line in lines:
		if "FMfcgxvzKb" in line:
			print(line)
		line = line.lower().replace("\\", "/")
		splitted_line = line.split(",")
		if len(splitted_line) < 15:
			continue
		
		# DNS
		if len(splitted_line[1]) > 0 and len(splitted_line[2]) > 0:
			edge_type = "resolve"
			edge_label = edge_type + "_" + str(splitted_line[0])
			domain_name = splitted_line[1]
			IP_Address = splitted_line[2] #.replace(":", "_")
			if int(splitted_line[0]) >= StartTime:
				if not G.has_node(domain_name):
					G.add_node(domain_name, type="domain_name", timestamp=splitted_line[0])
				if not G.has_node(IP_Address):
					G.add_node(IP_Address, type="IP_Address", timestamp=splitted_line[0])
				if not G.has_edge(domain_name, IP_Address):
					G.add_edge(domain_name, IP_Address, capacity=1.0, label=edge_label, type=edge_type , timestamp=splitted_line[0])
		
		# web_object to domain_name (in referal)
		if len(splitted_line[15]) > 0 and not splitted_line[15].startswith("/"): #  and not splitted_line[15].startswith("/") and "/" in splitted_line[15]
			edge_type = "web_request"
			domain_name = splitted_line[15]
			if ":" in domain_name:
				domain_name = domain_name.split(":")[0]
			if "://" in domain_name:
				domain_name = domain_name.split("://")[1]
			if "/" in domain_name:
				domain_name = domain_name[:domain_name.find("/")]
			web_object = splitted_line[15] # .replace(":", "_")
			if not "/" in web_object:
				web_object += "/"
			if "//" in web_object:
				web_object = web_object.replace("//", "/")
			edge_label = edge_type + "_" + str(splitted_line[0])
			if int(splitted_line[0]) >= StartTime:
				if not G.has_node(domain_name):
					G.add_node(domain_name, type="domain_name", timestamp=splitted_line[0])
				if not G.has_node(web_object):
					G.add_node(web_object, type="web_object", timestamp=splitted_line[0])
				if not G.has_edge(web_object, domain_name):
					G.add_edge(web_object, domain_name, capacity=1.0, label=edge_label, type=edge_type , timestamp=splitted_line[0])

		# web_object to domain_name
		if len(splitted_line[14]) > 0:
			edge_type = "web_request"
			domain_name = splitted_line[14]
			if ":" in domain_name:
				domain_name = domain_name[:domain_name.find(":")]
			if "/" in domain_name:
				domain_name = domain_name[:domain_name.find("/")]
			web_object = splitted_line[14]
			if not "/" in web_object:
				web_object += "/"
			web_object = web_object # .replace(":", "_")
			if len(splitted_line[11]) > 0:
				url = splitted_line[11] # .replace(":", "_")
				if url.startswith("/"):
					web_object = splitted_line[14] + url # .replace(":", "_") splitted_line[14].replace(":", "_") 
				else:
					#web_object = splitted_line[14].replace(":", "_") + "/" + url.replace(":", "_")
					web_object = splitted_line[11] # .replace(":", "_")
			elif len(splitted_line[12]) > 0:
				url = splitted_line[12]
				if url.startswith("/"):
					web_object = splitted_line[14] + url # .replace(":", "_") splitted_line[14].replace(":", "_")
				else:
					#web_object = splitted_line[14].replace(":", "_") + "/" + url.replace(":", "_")
					web_object = splitted_line[12] # .replace(":", "_")
			edge_label = edge_type + "_" + str(splitted_line[0])
			web_object = web_object.replace("//", "/")
			if int(splitted_line[0]) >= StartTime:
				if not G.has_node(domain_name):
					G.add_node(domain_name, type="domain_name", timestamp=splitted_line[0])
				if not G.has_node(web_object):
					G.add_node(web_object, type="web_object", timestamp=splitted_line[0])
				if not G.has_edge(web_object, domain_name):
					G.add_edge(web_object, domain_name, capacity=1.0, label=edge_label, type=edge_type , timestamp=splitted_line[0])
			# web_object (from referal) to web_object in request/response
			if len(splitted_line[15]) > 0:
				edge_type = "refer"
				edge_label = edge_type + "_" + str(splitted_line[0])
				web_object0 = splitted_line[15] # .replace(":", "_")
				if int(splitted_line[0]) >= StartTime:
					if not G.has_node(web_object0):
						G.add_node(web_object0, type="web_object", timestamp=splitted_line[0])
					if not G.has_node(web_object):
						G.add_node(web_object, type="web_object", timestamp=splitted_line[0])
					if not G.has_edge(web_object, web_object0):
						G.add_edge(web_object, web_object0, capacity=1.0, label=edge_label, type=edge_type , timestamp=splitted_line[0])
		
		# POST web_object to domain_name
		elif len(splitted_line[12]) > 0:
			IsValidIP = False
			cleaned_ip = ""
			edge_type = "web_request"
			edge_label = edge_type + "_" + str(splitted_line[0])
			domain_name = splitted_line[14]
			if not ":" in domain_name:
				IsValidIP = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain_name)
				if IsValidIP:
					cleaned_ip = domain_name
					domain_name += "_website"
			else:
				IsValidIP = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain_name.split(":")[0])
				if IsValidIP:
					cleaned_ip = domain_name.split(":")[0]
					domain_name = domain_name.split(":")[0] + "_website_" + domain_name.split(":")[1]
				else:
					domain_name = domain_name # .replace(":", "_")

			if "/" in domain_name:
				domain_name = domain_name[:domain_name.find("/")]

			web_object = domain_name + splitted_line[12]

			if not "/" in web_object:
				web_object += "/"

			if int(splitted_line[0]) >= StartTime:
				if not G.has_node(domain_name):
					G.add_node(domain_name, type="domain_name", timestamp=splitted_line[0])
				if not G.has_node(web_object):
					G.add_node(web_object, type="web_object", timestamp=splitted_line[0])
				if not G.has_edge(web_object, domain_name):
					G.add_edge(web_object, domain_name, capacity=1.0, label=edge_label, type=edge_type , timestamp=splitted_line[0])
				if IsValidIP:
					edge_type = "resolve"
					edge_label = edge_type + "_" + str(splitted_line[0])
					if not G.has_node(cleaned_ip):
						G.add_node(cleaned_ip, type="IP_Address", timestamp=splitted_line[0])
					if not G.has_edge(domain_name, cleaned_ip):
						G.add_edge(domain_name, cleaned_ip, capacity=1.0, label=edge_label, type=edge_type , timestamp=splitted_line[0])

			if len(splitted_line[15]) > 0:
				IsValidIP = False
				cleaned_ip = ""
				edge_type = "refer"
				edge_label = edge_type + "_" + str(splitted_line[0])
				domain_name = splitted_line[15]
				if not ":" in domain_name:
					IsValidIP = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain_name)
					if IsValidIP:
						cleaned_ip = domain_name
						domain_name += "_website"
				else:
					IsValidIP = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain_name.split(":")[0])
					if IsValidIP:
						cleaned_ip = domain_name.split(":")[0]
						domain_name = domain_name.split(":")[0] + "_website_" + domain_name.split(":")[1]
					else:
						domain_name = domain_name # .replace(":", "_")
	
				if "/" in domain_name:
					domain_name = domain_name[:domain_name.find("/")]
	
				if int(splitted_line[0]) >= StartTime:
					if not G.has_node(domain_name):
						G.add_node(domain_name, type="domain_name", timestamp=splitted_line[0])
					if not G.has_node(web_object):
						G.add_node(web_object, type="web_object", timestamp=splitted_line[0])
					if not G.has_edge(web_object, domain_name):
						G.add_edge(web_object, domain_name, capacity=1.0, label=edge_label, type=edge_type , timestamp=splitted_line[0])
					if IsValidIP:
						edge_type = "resolve"
						edge_label = edge_type + "_" + str(splitted_line[0])
						if not G.has_node(cleaned_ip):
							G.add_node(cleaned_ip, type="IP_Address", timestamp=splitted_line[0])
						if not G.has_edge(domain_name, cleaned_ip):
							G.add_edge(domain_name, cleaned_ip, capacity=1.0, label=edge_label, type=edge_type , timestamp=splitted_line[0])

		# GET
		elif len(splitted_line[11]) > 0:
			IsValidIP = False
			cleaned_ip = ""
			edge_type = "web_request"
			edge_label = edge_type + "_" + str(splitted_line[0])
			domain_name = splitted_line[11]
			if not "/" in splitted_line[11]:
				domain_name = splitted_line[11]
			else:
				domain_name = splitted_line[11][:splitted_line[11].find("/")]
			
			if not ":" in domain_name:
				IsValidIP = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain_name)
				if IsValidIP:
					cleaned_ip = domain_name
					domain_name += "_website"
			else:
				IsValidIP = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain_name.split(":")[0])
				if IsValidIP:
					cleaned_ip = domain_name.split(":")[0]
					domain_name = domain_name.split(":")[0] + "_website_" + domain_name.split(":")[1]
				else:
					domain_name = domain_name # .replace(":", "_")

			if "/" in domain_name:
				domain_name = domain_name[:domain_name.find("/")]

			web_object = domain_name + splitted_line[11][splitted_line[11].find("/"):] # .replace(":", "_")

			if not "/" in web_object:
				web_object += "/"

			if int(splitted_line[0]) >= StartTime:
				if not G.has_node(domain_name):
					G.add_node(domain_name, type="domain_name", timestamp=splitted_line[0])
				if not G.has_node(web_object):
					G.add_node(web_object, type="web_object", timestamp=splitted_line[0])
				if not G.has_edge(web_object, domain_name):
					G.add_edge(web_object, domain_name, capacity=1.0, label=edge_label, type=edge_type , timestamp=splitted_line[0])
				if IsValidIP:
					edge_type = "resolve"
					edge_label = edge_type + "_" + str(splitted_line[0])
					if not G.has_node(cleaned_ip):
						G.add_node(cleaned_ip, type="IP_Address", timestamp=splitted_line[0])
					if not G.has_edge(domain_name, cleaned_ip):
						G.add_edge(domain_name, cleaned_ip, capacity=1.0, label=edge_label, type=edge_type , timestamp=splitted_line[0])


			if len(splitted_line[15]) > 0:
				IsValidIP = False
				cleaned_ip = ""
				edge_type = "refer"
				edge_label = edge_type + "_" + str(splitted_line[0])
				domain_name = splitted_line[15]
				if not ":" in domain_name:
					IsValidIP = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain_name)
					if IsValidIP:
						cleaned_ip = domain_name
						domain_name += "_website"
				else:
					IsValidIP = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain_name.split(":")[0])
					if IsValidIP:
						cleaned_ip = domain_name.split(":")[0]
						domain_name = domain_name.split(":")[0] + "_website_" + domain_name.split(":")[1]
					else:
						domain_name = domain_name  # .replace(":", "_")
	
				if "/" in domain_name:
					domain_name = domain_name[:domain_name.find("/")]
	
				if int(splitted_line[0]) >= StartTime:
					if not G.has_node(domain_name):
						G.add_node(domain_name, type="domain_name", timestamp=splitted_line[0])
					if not G.has_node(web_object):
						G.add_node(web_object, type="web_object", timestamp=splitted_line[0])
					if not G.has_edge(web_object, domain_name):
						G.add_edge(web_object, domain_name, capacity=1.0, label=edge_label, type=edge_type , timestamp=splitted_line[0])
					if IsValidIP:
						edge_type = "resolve"
						edge_label = edge_type + "_" + str(splitted_line[0])
						if not G.has_node(cleaned_ip):
							G.add_node(cleaned_ip, type="IP_Address", timestamp=splitted_line[0])
						if not G.has_edge(domain_name, cleaned_ip):
							G.add_edge(domain_name, cleaned_ip, capacity=1.0, label=edge_label, type=edge_type , timestamp=splitted_line[0])


		if len(splitted_line[3]) > 0:
			# create the current line process
			pid = splitted_line[3]
			program_name = splitted_line[5]
			node_name = program_name + "_" + pid
			if len(program_name) == 0 or len(pid) == 0:
				if len(pid) == 0:
					pid = "NOPID"
				if len(program_name) == 0:
					program_name = "NOPROCESSNAME"
				node_name = program_name + "_" + pid
			else:
				processes[pid] = program_name
			node_name = str(node_name)
	
			if program_name.startswith("/device/harddiskvolume1"):
				program_name = program_name.replace("/device/harddiskvolume1", "c:")
				node_name = node_name.replace("/device/harddiskvolume1", "c:")
			
			if not G.has_node(node_name) and not node_name == "NOPROCESSNAME" and not node_name == "NOPROCESSNAME_NOPID":
				#print node_name
				if int(splitted_line[0]) >= StartTime:
					G.add_node(node_name, type="process", timestamp=splitted_line[0])
					if program_name.endswith("/") and not program_name.endswith("//"):
						program_name = program_name[:len(program_name)-1] + "//"
					if not program_name == "NOPROGRAMNAME":
						program_name = program_name.rstrip()
						if not G.has_node(program_name):
							G.add_node(program_name, type="file", timestamp=splitted_line[0])
						if IncludeExecutedEdges:
							edge_type = "executed"
							edge_label = edge_type + "_" + str(0)
							G.add_edge(node_name, program_name, capacity=1.0, label=edge_label, type=edge_type , timestamp=splitted_line[0])
			
			# create a direct edge from parent to current line process
			if len(splitted_line[4]) > 0:
				parent_node_name = ""
				parent_pid = splitted_line[4]
				parent_name = ""
				if parent_pid in processes.keys():
					parent_name = processes[parent_pid]
				else:
					parent_name = "NOPROCESSNAME"
				parent_node_name = parent_name + "_" + parent_pid
				parent_node_name = str(parent_node_name)
				if parent_node_name.startswith("/device/harddiskvolume1"):
					parent_name = parent_name.replace("/device/harddiskvolume1", "c:")
					parent_node_name = parent_node_name.replace("/device/harddiskvolume1", "c:")
				
				if not G.has_node(parent_node_name) and not parent_node_name == "NOPROCESSNAME" and not parent_node_name == "NOPROCESSNAME_NOPID":
					if int(splitted_line[0]) >= StartTime:
						G.add_node(parent_node_name, type="process", timestamp=splitted_line[0])
						if not parent_name == "NOPROCESSNAME":
							if not G.has_node(parent_name):
								if parent_name.endswith("/"):
									parent_name = parent_name[:len(parent_name)-1] + "//"
								G.add_node(parent_name, type="file", timestamp=splitted_line[0])
							if IncludeExecutedEdges:
								edge_type = "executed"
								edge_label = edge_type + "_" + str(0)
								G.add_edge(parent_node_name, parent_name, capacity=1.0, label=edge_label, type=edge_type , timestamp=splitted_line[0])
				
				edge_type = "fork"
				edge_label = edge_type + "_" + str(splitted_line[0])
				if int(splitted_line[0]) >= StartTime:
					if not G.has_edge(node_name, parent_node_name): # if not parent_node_name in G.successors(node_name)
						G.add_edge(node_name, parent_node_name, capacity=1.0, label=edge_label, type=edge_type , timestamp=splitted_line[0])
					else:
						ALREADY_ADDED = False
						for e in G.edges(node_name, data=True):
							if e[2]['label'].startswith(edge_type):
								ALREADY_ADDED = True
								break
						if not ALREADY_ADDED:
							G.add_edge(node_name, parent_node_name, capacity=1.0, label=edge_label, type=edge_type , timestamp=splitted_line[0])
	
			if len(splitted_line[8]) > 0:
				d_ip = splitted_line[8]
				d_port = str(0)
	
				if len(splitted_line[9]) > 0:
					d_port = splitted_line[9]
	
				d_ip = d_ip # .replace(":", "_")

				s_ip = splitted_line[6]
				s_port = str(0)
	
				if len(splitted_line[7]) > 0:
					s_port = splitted_line[7]
	
				s_ip = s_ip # .replace(":", "_")

				joint_ips = ""
				joint_ips1 = s_ip + "_" + d_ip
				joint_ips2 = d_ip + "_" + s_ip

				if not G.has_node(joint_ips1) and not G.has_node(joint_ips2):
					if int(splitted_line[0]) >= StartTime:
						joint_ips = "connection_" + joint_ips1
						G.add_node(joint_ips, type="connection", timestamp=splitted_line[0])
				else:
					if G.has_node(joint_ips1):
						if int(splitted_line[0]) >= StartTime:
							joint_ips = joint_ips1
					else:
						if int(splitted_line[0]) >= StartTime:
							joint_ips = joint_ips2

				if not G.has_node(s_ip):
					if int(splitted_line[0]) >= StartTime:
						G.add_node(s_ip, type="IP_Address", timestamp=splitted_line[0])
				if not G.has_node(d_ip):
					if int(splitted_line[0]) >= StartTime:
						G.add_node(d_ip, type="IP_Address", timestamp=splitted_line[0])

				# this block is to connect the remote IP to process, joint_ips connection and local ports
				edge_type = "connected_remote_ip"
				edge_label = edge_type + "_" + str(splitted_line[0])
				if int(splitted_line[0]) >= StartTime:
					if s_ip == hosts_ips[0]: #if s_ip == "0.0.0.0" or s_ip == "127.0.0.1" or 
						if not G.has_edge(d_ip, node_name): # .encode('unicode_escape')
							G.add_edge(d_ip, node_name, capacity=1.0, label=edge_label, type=edge_type , timestamp=splitted_line[0], ip=d_ip)
						if not G.has_edge(d_ip, joint_ips): # .encode('unicode_escape')
							G.add_edge(d_ip, joint_ips, capacity=1.0, label=edge_label, type=edge_type , timestamp=splitted_line[0], ip=d_ip)
					elif d_ip == hosts_ips[0]:
						if not G.has_edge(s_ip, node_name): # .encode('unicode_escape')
							G.add_edge(s_ip, node_name, capacity=1.0, label=edge_label, type=edge_type , timestamp=splitted_line[0], ip=s_ip)
						if not G.has_edge(s_ip, joint_ips): # .encode('unicode_escape')
							G.add_edge(s_ip, joint_ips, capacity=1.0, label=edge_label, type=edge_type , timestamp=splitted_line[0], ip=s_ip)

				edge_type = "connect"
				edge_label = edge_type + "_" + str(splitted_line[0])
				if int(splitted_line[0]) >= StartTime:
					if not G.has_edge(joint_ips, node_name): # .encode('unicode_escape')
						G.add_edge(joint_ips, node_name, capacity=1.0, label=edge_label, type=edge_type , timestamp=splitted_line[0], sip=s_ip, sport=s_port, dip=d_ip, dport=d_port)
					else:
						ALREADY_ADDED = False
						for e in G.edges(joint_ips, data=True):
							if e[2]['type'] == edge_type and e[2]['sip'] == s_ip and e[2]['sport'] == s_port and e[2]['dip'] == d_ip and e[2]['dport'] == d_port:
								ALREADY_ADDED = True
								break
						if not ALREADY_ADDED:
							G.add_edge(joint_ips, node_name, capacity=1.0, label=edge_label, type=edge_type , timestamp=splitted_line[0], sip=s_ip, sport=s_port, dip=d_ip, dport=d_port)
				
				edge_type = "sock_send"
				edge_label = edge_type + "_" + str(splitted_line[0])
				sender = "session_"+s_ip+"_"+s_port
				if not G.has_node(sender):
					if int(splitted_line[0]) >= StartTime:
						G.add_node(sender, type="session", timestamp=splitted_line[0], ip=s_ip, port=s_port)
				
				receiver = "session_"+d_ip+"_"+d_port
				if not G.has_node(receiver):
					if int(splitted_line[0]) >= StartTime:
						G.add_node(receiver, type="session", timestamp=splitted_line[0], ip=d_ip, port=d_port)

				if not G.has_edge(receiver, sender): # .encode('unicode_escape')
					G.add_edge(receiver, sender, capacity=1.0, label=edge_label, type=edge_type , timestamp=splitted_line[0], sip=s_ip, sport=s_port, dip=d_ip, dport=d_port)
				
				edge_type = "bind"
				edge_label = edge_type + "_" + str(splitted_line[0])

				if s_ip == hosts_ips[0]: #s_ip == "0.0.0.0" or s_ip == "127.0.0.1" or 
					if not G.has_edge(sender, node_name): # .encode('unicode_escape')
						G.add_edge(sender, node_name, capacity=1.0, label=edge_label, type=edge_type , timestamp=splitted_line[0], ip=s_ip, port=s_port)
					edge_type = "connected_session"
					edge_label = edge_type + "_" + str(splitted_line[0])
					if not G.has_edge(d_ip, sender): # .encode('unicode_escape')
						G.add_edge(d_ip, sender, capacity=1.0, label=edge_label, type=edge_type , timestamp=splitted_line[0], ip=s_ip, port=s_port)
				elif d_ip == hosts_ips[0]:
					if not G.has_edge(receiver, node_name): # .encode('unicode_escape')
						G.add_edge(receiver, node_name, capacity=1.0, label=edge_label, type=edge_type , timestamp=splitted_line[0], ip=d_ip, port=d_port)
					edge_type = "connected_session"
					edge_label = edge_type + "_" + str(splitted_line[0])
					if not G.has_edge(s_ip, receiver): # .encode('unicode_escape')
						G.add_edge(s_ip, receiver, capacity=1.0, label=edge_label, type=edge_type , timestamp=splitted_line[0], ip=d_ip, port=d_port)

			if len(splitted_line[17]) > 0 and splitted_line[17].startswith("file_") and len(splitted_line[18]) > 0:
				accesses = splitted_line[17].rstrip()
				file_name = splitted_line[18].rstrip()
	
				if int(splitted_line[0]) >= StartTime:
					if not G.has_node(file_name):
						if file_name.endswith("/") and not file_name.endswith("//"):
							file_name = file_name[:len(file_name)-1] + "//"
						G.add_node(file_name, type="file", timestamp=splitted_line[0])
	
				for edge_type in ["readdata", "write", "delete", "execute"]: #"readdata", "writedata"
					src_node = file_name
					dst_node = node_name
					if edge_type in accesses and not "attribute" in accesses: 
						if edge_type == "readdata":
							edge_type = "read"
						if edge_type == "write":
							edge_type = "write"
						edge_label = edge_type + "_" + str(splitted_line[0])

						#"execute" is not like fork, it is more like read, as it goes for every
						#module gets executed under every process that executes that module.
						if edge_type == "read" or edge_type == "execute": # 
							src_node = node_name
							dst_node = file_name
						if int(splitted_line[0]) >= StartTime:
							if not G.has_edge(src_node, dst_node): # .encode('unicode_escape')
								G.add_edge(src_node, dst_node, capacity=1.0, label=edge_label, type=edge_type , timestamp=splitted_line[0])
							else:
								ALREADY_ADDED = False
								for e in G.edges(src_node, data=True):
									if e[2]['label'].startswith(edge_type):
										ALREADY_ADDED = True
										break
								if not ALREADY_ADDED:
									G.add_edge(src_node, dst_node, capacity=1.0, label=edge_label, type=edge_type , timestamp=splitted_line[0])
						
						if edge_type == "write":
							downloaded_file_name = file_name



# This is for exploring the graph to find the subgraph
def construct_G_subgraph():
	global sub_nodes, node_set, G_subgraph, G

	sub_nodes = [user_node]
	node_set = set(sub_nodes)
	FOUND_NEW_NODES = True

	while True:
		if FOUND_NEW_NODES:
			FOUND_NEW_NODES = False
		else:
			break
	
		for n in sub_nodes:
		    successors = G.successors(n) # or neighbors
		    predecessors = G.predecessors(n)
	
		    before_union_size = len(node_set)
		    node_set = node_set.union(successors)
		    node_set = node_set.union(predecessors)
		    after_union_size = len(node_set)
	
		    if after_union_size > before_union_size:
		    	FOUND_NEW_NODES = True
	
		sub_nodes = list(node_set)
	
	G_subgraph = G.subgraph(sub_nodes).copy()

#Now let us find the root nodes which are reachable from the user-defined node
def find_G_subgraph_potential_roots():
	global sub_root_nodes, node_set, G_subgraph, found_roots

	sub_root_nodes = [user_node]
	node_set = set(sub_root_nodes)
	FOUND_NEW_NODES = True

	while True:
		if FOUND_NEW_NODES:
			FOUND_NEW_NODES = False
		else:
			break
	
		for n in sub_root_nodes:
			successors = list(G_subgraph.successors(n))
			predecessors = list(G_subgraph.predecessors(n))
			n_type = G_subgraph.nodes(data=True)[n]['type']

			if not n in found_roots and ".exe_" in n and n_type == "process" and len(list(G_subgraph.successors(n))) == 0: #  
				found_roots.append(n)
	
			before_union_size = len(node_set)
			node_set = node_set.union(successors)
			after_union_size = len(node_set)
	
			if after_union_size > before_union_size:
				FOUND_NEW_NODES = True
	
		sub_root_nodes = list(node_set)

def explore_roots():
	global found_roots, ROOT_sub_nodes, G_subgraph, ROOT_G_subgraph, ROOT

	for n in found_roots:

		ROOT_sub_nodes = [n]
		ROOT_node_set = set(ROOT_sub_nodes)
		FOUND_NEW_NODES = True
	
		while True:
			if FOUND_NEW_NODES:
				FOUND_NEW_NODES = False
			else:
				break
	
			for nn in ROOT_sub_nodes:
				successors = G_subgraph.successors(nn)	
				predecessors = G_subgraph.predecessors(nn)
				before_union_size = len(ROOT_node_set)
				ROOT_node_set = ROOT_node_set.union(successors)
				ROOT_node_set = ROOT_node_set.union(predecessors)
				after_union_size = len(ROOT_node_set)
		
				if after_union_size > before_union_size:
					FOUND_NEW_NODES = True
		
				ROOT_sub_nodes = list(ROOT_node_set)
	
		ROOT = n
		ROOT_G_subgraph = G_subgraph.subgraph(ROOT_sub_nodes).copy()

def abstract_sessions():
	global ROOT_G_subgraph

	for n in ROOT_G_subgraph.nodes():
		sessions_to_be_abstracted = []

		if not n in ROOT_G_subgraph.nodes():
			continue

		n_type = ROOT_G_subgraph.nodes(data=True)[n]['type']
		if not n_type == "session": # we only optimize file leaf nodes
			continue

		sessions_to_be_abstracted.append(n)

		n_ip = ROOT_G_subgraph.nodes(data=True)[n]['ip']
		n_port = ROOT_G_subgraph.nodes(data=True)[n]['port']
		n_successors = list(ROOT_G_subgraph.successors(n))
		n_predecessors = list(ROOT_G_subgraph.predecessors(n))
		n_out_edges = list(ROOT_G_subgraph.out_edges(n))
		n_in_edges = list(ROOT_G_subgraph.in_edges(n))
		for m in ROOT_G_subgraph.nodes():
			if n == m:
				continue

			m_type = ROOT_G_subgraph.nodes(data=True)[m]['type']
			if not m_type == "session": # we only optimize file leaf nodes
				continue
			
			m_ip = ROOT_G_subgraph.nodes(data=True)[m]['ip']
			m_port = ROOT_G_subgraph.nodes(data=True)[m]['port']
			if not n_ip == m_ip:
				continue
			
			m_successors = list(ROOT_G_subgraph.successors(m))
			m_predecessors = list(ROOT_G_subgraph.predecessors(m))
			m_out_edges = list(ROOT_G_subgraph.out_edges(m))
			m_in_edges = list(ROOT_G_subgraph.in_edges(m))
			if len(n_successors) == len(m_successors):
				if len(n_predecessors) == len(m_predecessors):
					if n_successors == m_successors:
						if n_predecessors == m_predecessors:
							if len(n_out_edges) == len(m_out_edges) and len(n_in_edges) == len(m_in_edges):
								#print m
								sessions_to_be_abstracted.append(m)
		
		if len(sessions_to_be_abstracted) > 1:
			res_leaf = n
			for one_session in sessions_to_be_abstracted[1:]:
				res_leaf += ";" + one_session[one_session.rfind("_")+1:]

			mapping = {n: res_leaf}
			ROOT_G_subgraph = nx.relabel_nodes(ROOT_G_subgraph, mapping)

			for one_session in sessions_to_be_abstracted[1:]:
				ROOT_G_subgraph.remove_node(one_session)

# could have used G.out_degree(x)==0 and G.in_degree(x)==1) to find leaf nodes
def abstract_leaf_nodes():
	global abstractd_leaf_nodes, ROOT_sub_nodes, sub_nodes, G_subgraph, ROOT_G_subgraph, G, sub_abstractd_leaf_nodes, sub_nodes_leaf_nodes, total_nodes_in_sets

	for n in ROOT_sub_nodes:
		#print n
		#print ROOT_G_subgraph.nodes(data=True)[n]
		n_type = ROOT_G_subgraph.nodes(data=True)[n]['type']
		if n == ROOT:
			continue
		if not n_type == "file": # we only optimize file leaf nodes
			continue
		successors = list(ROOT_G_subgraph.successors(n))
		predecessors = list(ROOT_G_subgraph.predecessors(n))
		if len(predecessors) == 0 or len(successors) == 0:
			sub_nodes_leaf_nodes.append(n)
		elif len(predecessors) == 1 and len(successors) == 1 and predecessors == successors:
			sub_nodes_leaf_nodes.append(n)
	
	sub_abstractd_leaf_nodes = sub_nodes_leaf_nodes
	total_nodes_in_sets = ""

	while True:
		if len(sub_abstractd_leaf_nodes) == 0: # to quit the infinite loop
			break

		for n in sub_abstractd_leaf_nodes:
			n_list = None
			n_node = ROOT_G_subgraph.nodes(data=True)[n]
			n_type = ROOT_G_subgraph.nodes(data=True)[n]['type']
			n_edges = ROOT_G_subgraph.out_edges(n,data=True)
			n_successors = list(ROOT_G_subgraph.successors(n)) # or neighbors
			n_predecessors = list(ROOT_G_subgraph.predecessors(n))
			n_LeafTType = 1
			
			if len(n_successors) == 0:
				n_LeafTType = 2
				n_edges = ROOT_G_subgraph.in_edges(n, data=True)
			
			if len(n_successors) == 1 and len(n_predecessors) == 1 and list(n_successors) == list(n_predecessors):
				n_LeafTType = 3
				n_edges = [ROOT_G_subgraph.in_edges(n, data=True), ROOT_G_subgraph.out_edges(n, data=True)]

			if len(n_edges) == 0:
				print("1- Error: is this a disconnected node? " + n)

			if n_LeafTType == 1:
				n_list = [n, 1, n_node, n_edges] # True this is lower leaf
			elif n_LeafTType == 2:
				n_list = [n, 2, n_node, n_edges] # True this is upper leaf
			elif n_LeafTType == 3:
				n_list = [n, 3, n_node, n_edges] # 1-leaf-1

			for m in sub_abstractd_leaf_nodes:
				if n == m:
					continue
				m_node = ROOT_G_subgraph.nodes(data=True)[m]
				m_type = ROOT_G_subgraph.nodes(data=True)[m]['type']
				m_successors = list(ROOT_G_subgraph.successors(m))
				m_predecessors = list(ROOT_G_subgraph.predecessors(m))
				m_edges = ROOT_G_subgraph.out_edges(m,data=True)
				m_LeafTType = 1
			
				if len(m_successors) == 0:
					m_LeafTType = 2
					m_edges = ROOT_G_subgraph.in_edges(m, data=True)
				elif len(m_successors) == 1 and len(m_predecessors) == 1 and m_successors == m_predecessors:
					m_LeafTType = 3
					m_edges = [ROOT_G_subgraph.in_edges(m, data=True), ROOT_G_subgraph.out_edges(m, data=True)]

				if len(m_edges) == 0:
					print("2- Error: is this a disconnected node? " + m)
	
				if not n == m: # not same node and both have same node type
					if n_LeafTType == m_LeafTType == 1:
						if not len(n_edges) == len(m_edges):
							continue
						if not n_successors == m_successors:
							continue
					elif n_LeafTType == m_LeafTType == 2:
						if not len(n_edges) == len(m_edges):
							continue
						if not n_predecessors == m_predecessors:
							continue
					elif n_LeafTType == 3 and m_LeafTType == 3:
						if not len(n_edges[0]) == len(m_edges[0]):
							continue
						if not n_successors == m_successors:
							continue
						if not len(n_edges[1]) == len(m_edges[1]):
							continue
						if not n_predecessors == m_predecessors:
							continue
					
					if n_successors == m_successors or n_predecessors == m_predecessors and n_type == m_type: # same succssors
						MISSED_EDGE = False
						
						if (n_LeafTType == 1 and m_LeafTType == 1) or (n_LeafTType == 2 and m_LeafTType == 2):
							for e1 in n_edges:
								FOUND_EDGE = False
								for e2 in m_edges:
									if e1[2]['type'] == e2[2]['type'] and (e1[1] == e2[1] or e1[0] == e2[0]): #((e1[1] == e2[1] and e1[0] == [] and e2[0] == []) or (e1[0] == e2[0] and e1[1] == [] and e2[1] == []))
										FOUND_EDGE = True
										break
								if not FOUND_EDGE:
									MISSED_EDGE = True
									break
							if not MISSED_EDGE:
								n_list.append(m)
								IS_OLDEST = False
						elif n_LeafTType == 3 and m_LeafTType == 3:
							for e1 in n_edges[0]:
								FOUND_EDGE = False
								for e2 in m_edges[0]:
									if e1[2]['type'] == e2[2]['type'] and (e1[1] == e2[1] or e1[0] == e2[0]): #((e1[1] == e2[1] and e1[0] == [] and e2[0] == []) or (e1[0] == e2[0] and e1[1] == [] and e2[1] == []))
										FOUND_EDGE = True
										break
								if not FOUND_EDGE:
									MISSED_EDGE = True
									break
							if not MISSED_EDGE:
								for e1 in n_edges[1]:
									FOUND_EDGE = False
									for e2 in m_edges[1]:
										if e1[2]['type'] == e2[2]['type'] and (e1[1] == e2[1] or e1[0] == e2[0]): #((e1[1] == e2[1] and e1[0] == [] and e2[0] == []) or (e1[0] == e2[0] and e1[1] == [] and e2[1] == []))
											FOUND_EDGE = True
											break
									if not FOUND_EDGE:
										MISSED_EDGE = True
										break
							if not MISSED_EDGE:
								n_list.append(m)
								IS_OLDEST = False
			total_nodes_in_sets += str(len(n_list)-3) + ", "
			abstractd_leaf_nodes.append(n_list)
			res_leaf = n
			
			if len(n_list) > 4:
				n_timestamp = ROOT_G_subgraph.nodes(data=True)[n]['timestamp']
				for m in n_list[4:]:
					m_timestamp = ROOT_G_subgraph.nodes(data=True)[m]['timestamp']
					if int(m_timestamp) < int(n_timestamp):
						n_list[2]["timestamp"] = m_timestamp
						ROOT_G_subgraph.nodes(data=True)[n]['timestamp'] = ROOT_G_subgraph.nodes(data=True)[m]['timestamp']
						if n_list[1]:
							for e1 in ROOT_G_subgraph.out_edges(n,data=True):
								for e2 in ROOT_G_subgraph.out_edges(m,data=True):
									if e1[2]['type'] == e2[2]['type']:
										if e1[1] == e2[1]:
											e1[2]['timestamp'] = e2[2]['timestamp']
											e1[2]['label'] = e2[2]['label']
						elif not n_list[1]:
							for e1 in ROOT_G_subgraph.in_edges(n,data=True):
								for e2 in ROOT_G_subgraph.in_edges(m,data=True):
									if e1[2]['type'] == e2[2]['type']:
										if e1[0] == e2[0]:
											e1[2]['timestamp'] = e2[2]['timestamp']
											e1[2]['label'] = e2[2]['label']
						elif n_list[1] == None:
							for e1 in ROOT_G_subgraph.in_edges(n,data=True):
								for e2 in ROOT_G_subgraph.in_edges(m,data=True):
									if e1[2]['type'] == e2[2]['type']:
										if e1[0] == e2[0]:
											e1[2]['timestamp'] = e2[2]['timestamp']
											e1[2]['label'] = e2[2]['label']
							for e1 in ROOT_G_subgraph.out_edges(n,data=True):
								for e2 in ROOT_G_subgraph.out_edges(m,data=True):
									if e1[2]['type'] == e2[2]['type']:
										if e1[1] == e2[1]:
											e1[2]['timestamp'] = e2[2]['timestamp']
											e1[2]['label'] = e2[2]['label']
					
				for leaf_node in n_list[4:]:
					res_leaf += ";" + leaf_node
				
				mapping = {n: res_leaf}
				ROOT_G_subgraph = nx.relabel_nodes(ROOT_G_subgraph, mapping)
				
				for leaf_node in n_list[4:]:
					ROOT_G_subgraph.remove_node(leaf_node)
				sub_abstractd_leaf_nodes = list(set(sub_abstractd_leaf_nodes).difference(set(n_list[4:])))
		
			if n in sub_abstractd_leaf_nodes:
				sub_abstractd_leaf_nodes.remove(n)
			
			n_list = None
			break

def load_user_artifact(file):
	
	mlabels_file = ""
	training_prefix = "training_preprocessed_logs_"
	testing_prefix = "testing_preprocessed_logs_"
	
	if training_prefix in file:
		logs_folder = file.split(training_prefix)[1]
	if testing_prefix in file:
		logs_folder = file.split(testing_prefix)[1]
	
	if file.startswith(training_prefix):
		ua_file = open("training_logs/" + logs_folder + "/user_artifact.txt")
	if file.startswith(testing_prefix):
		ua_file = open("testing_logs/" + logs_folder + "/user_artifact.txt")
	
	return ua_file.readline().lower()

def load_hosts_ips(file):
	global hosts_ips

	hosts_ips = []
	training_prefix = "training_preprocessed_logs_"
	testing_prefix = "testing_preprocessed_logs_"
	if training_prefix in file:
		logs_folder = file.split(training_prefix)[1]
	if testing_prefix in file:
		logs_folder = file.split(testing_prefix)[1]

	if file.startswith(training_prefix):
		ip_file = open("training_logs/" + logs_folder + "/ips.txt")
		hosts_ips = ip_file.readlines()
		
	if file.startswith(testing_prefix):
		ip_file = open("testing_logs/" + logs_folder + "/ips.txt")
		hosts_ips = ip_file.readlines()
	
	for ip in range(0, len(hosts_ips)):
		hosts_ips[ip] = hosts_ips[ip].lower().rstrip()


if __name__ == '__main__':
	user_node = ""
	for file in os.listdir("output"):
		if file.startswith("training_preprocessed_logs") or file.startswith("testing_preprocessed_logs"):

			start = time.time()

			user_node = load_user_artifact(file)
			load_hosts_ips(file)
			print(hosts_ips)
			print("\nuser_artifact is: " + user_node)
			log_file_name = ""
			ROOT = None
			sub_nodes = [user_node]
			node_set = set(sub_nodes)
			ROOT_G_subgraph = None
			ROOT_sub_nodes = []
			abstractd_leaf_nodes = []
			sub_nodes_leaf_nodes = []
			sub_abstractd_leaf_nodes = sub_nodes_leaf_nodes
			node_set_leaf_nodes = set(sub_nodes_leaf_nodes)
			log_file = None
			lines = []
			
			
			G = None
			G_subgraph = None
			processes = {}
			sub_root_nodes = [user_node]
			node_set = set(sub_root_nodes)
			found_roots = [user_node]
			total_nodes_in_sets = ""
			log_file_name = "output/" + file
			log_file = open(log_file_name,"r")
			lines = log_file.readlines()

			print("============\nprocessing the logs: " + log_file_name)

			construct_G()

			print("\nG:")
			print("nodes: " + str(len(G.nodes())))
			print("edges: " + str(len(G.edges())))

			if "linux" in file:
				G_subgraph = G
			else:
				construct_G_subgraph()
				
			print("\nG_subgraph:")
			print("nodes: " +  str(len(G_subgraph.nodes()))) 
			print("edges: " +  str(len(G_subgraph.edges()))) 

			ROOT_G_subgraph = G_subgraph
			ROOT_sub_nodes = G_subgraph.nodes()

			abstract_leaf_nodes()
			abstract_sessions()

			print("\nNumber of leaf nodes in ROOT_G_subgraph before abstraction: " + str(len(sub_nodes_leaf_nodes)))
			print("Number of leaf nodes in ROOT_G_subgraph after abstraction (i.e. leaf nodes with same successors/predecessors, types of edges and nodes): " + str(len(abstractd_leaf_nodes)))
			print("\nTotal number of nodes in each abstracted set: " + total_nodes_in_sets)
			
			if ROOT != 0:
				print("\nUser_artifact: " + str(ROOT))
			
			print("\nROOT_G_subgraph:")
			print("nodes: " + str(len(ROOT_G_subgraph.nodes())))
			print("edges: " + str(len(ROOT_G_subgraph.edges())))

			done = time.time()
			elapsed = done - start
			print("processing time: " + str(elapsed))

			# save graph in dot format
			# dot -Tpdf G_subgraph.dot -o G_subgraph.pdf
			# dot -Tpng G_subgraph.dot -o G_subgraph.png
			# dot G_subgraph.dot -Tjpg -o G_subgraph.jpg
			nx.nx_pydot.write_dot(ROOT_G_subgraph, "output/graph_" + file + ".dot")
