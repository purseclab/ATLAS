import re
import sys
import os
from datetime import *

ADJ_FF_TIME = -5
malicious_labels = []
preprocessing_lines = []
process_parent = {}

def order_events():
	global preprocessing_lines

	preprocessing_lines.sort()
	for i in range(0, len(preprocessing_lines)):
		node = preprocessing_lines[i]
		if "a" in node[:node.find(',')]:
			preprocessing_lines[i] = str(int(node[:node.find('a')])) + node[node.find(','):] + "\n"
		elif "b" in node[:node.find(',')]:
			preprocessing_lines[i] = str(int(node[:node.find('b')])) + node[node.find(','):] + "\n"
		elif "c" in node[:node.find(',')]:
			preprocessing_lines[i] = str(int(node[:node.find('c')])) + node[node.find(','):] + "\n"

def is_matched(string):
    for label in malicious_labels:
        if label in string:
            return True
    return False

# preprocess dns log
def pp_dns(wf, path):
    global preprocessing_lines

    log_file_path = path + '/dns'
    event_number = 1

    with open(log_file_path, 'r') as f:
        pre_out_line = ',' * 19
        for line in f:
            if not 'response' in line:
                continue
    
            out_line = ''
            splitted_line = line.split()
            no = splitted_line[0]
            time = splitted_line[1] + " " + splitted_line[2]
            ip_src = splitted_line[3]
            ip_dst = splitted_line[5]
            proto = splitted_line[6]
            length = splitted_line[7]
            info = ""
            for i in range(8, len(splitted_line)):
                info += splitted_line[i] + " "

            event_date = splitted_line[1]
            year, month, day = event_date.split('-')
            day_of_year = datetime(int(year), int(month), int(day)).timetuple().tm_yday
            date_val = str(int(day_of_year) * 24 * 60 * 60)

            timestamp = time.split()[1].split('.')[0]
            h, m, s = timestamp.split(':')
            out_line += str(int(h) * 3600 + int(m) * 60 + int(s) + int(date_val)).zfill(20) + "a" + str(event_number)
            event_number += 1
            # queried domain
            q_domain = re.findall(r'response 0x\S+ A+ (\S+) ', info)
            if q_domain:
                out_line += ',' + q_domain[0]
            else:
                out_line += ','
    
            # resolved ip
            r_ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', info)
            if r_ip:
                out_line += ',' + r_ip[0]
            else:
                out_line += ','
    
            # remaining fields is empty
            for i in range(0, 17):
                out_line += ','
    
            # write lines out, remove adjacent duplicate entries
            if len([(i, j) for i, j in zip(out_line.split(','), pre_out_line.split(',')) if i != j]) > 1:
                matched = False
                if is_matched(out_line):
                    matched = True
                if not ",,,,,,,,,,,,,,,,,,," in out_line:
                    if matched:
                        #wf.write(out_line + '-LD+\n')
                        preprocessing_lines.append('\n' + out_line.lower().replace("\\", "/") + '-LD+') #  + event_date + " " + timestamp
                    else:
                        #wf.write(out_line + '-LD-\n')
                        preprocessing_lines.append('\n' + out_line.lower().replace("\\", "/") + '-LD-') #  + event_date + " " + timestamp
                    pre_out_line = out_line


# preprocess audit log for windows x64 & x86
def pp_audit_w(wf, path):
    global preprocessing_lines

    timestamp = ""
    h, m, s = "", "", ""
    pid = 0
    ppid = 0
    new_pid = 0
    new_ppid = 0
    pname = ""
    first_iter = True
    d_ip = ""
    d_port = ""
    s_ip = ""
    s_port = ""
    acct = ""
    objname = ""
    log_file_path = path + '/security_events.txt'
    event_number = 1
    accesses_lines = False
    accesses = ""
    network_direction = ""

    with open(log_file_path, 'r') as f:
        f.readline()
        single_line = []
        inside_accesses_block = False
        accesses = "Accesses:"
        for line in f:
        	if line.lstrip().startswith("Accesses:") or inside_accesses_block:
        		access_line = line
        		if len(access_line.strip()) > 1:
        			if "Accesses:" in access_line:
        				inside_accesses_block = True
        				access_line = access_line.split("Accesses:")[1]
        			first_char_index = len(access_line) - len(access_line.lstrip())
        			access_line = access_line[first_char_index:]
        			last_char_index = len(access_line.rstrip())
        			access_line = access_line[:last_char_index]
        			access_line = access_line.replace(" ", "_")
        			accesses += "_" + access_line
        		else:
        			inside_accesses_block = False
        			single_line.append(accesses)
        			accesses = "Accesses:"
        	else:
        		single_line.append(line)

    # then for each log entry, compute domain
    pre_out_line = ',' * 19
    for entry in reversed(single_line):
        out_line = ''

        # timestamp
        if entry.startswith("Audit Success") or entry.startswith("Audit Failure") or entry.startswith("Information"):
            event_date = ""
            date_val = ""

            # timestamp 64-bit
            if entry.startswith("Information"):
                event_date = entry.split()[1]
                month, day, year = event_date.split('/')
                day_of_year = datetime(int(year), int(month), int(day)).timetuple().tm_yday
                date_val = str(int(day_of_year) * 24 * 60 * 60)

                timestamp = entry.split()[2]
                h, m, s = timestamp.split(':')
                if entry.split()[3] == "PM":
                    if 1 <= int(h) <= 11:
                        h = str(int(h) + 12)
                if entry.split()[3] == "AM":
                    if int(h) == 12:
                        h = "00"

            # timestamp 32-bit
            if entry.startswith("Audit Success") or entry.startswith("Audit Failure"):
                event_date = entry.split()[2]
                month, day, year = event_date.split('/')
                day_of_year = datetime(int(year), int(month), int(day)).timetuple().tm_yday
                date_val = str(int(day_of_year) * 24 * 60 * 60)

                timestamp = entry.split()[3]
                h, m, s = timestamp.split(':')
                if entry.split()[4] == "PM":
                    if 1 <= int(h) <= 11:
                        h = str(int(h) + 12)
                if entry.split()[4] == "AM":
                    if int(h) == 12:
                        h = "00"

            out_line = str(int(h) * 3600 + int(m) * 60 + int(s) + int(date_val)).zfill(20) + "b" + str(event_number)
            event_number += 1

            # queried domain
            out_line += ','
    
            # resolved ip
            out_line += ','

            if pid in process_parent:
                ppid = process_parent[pid]
            else:
                ppid = 0

            # pid
            if pid != 0:
                out_line += ',' + str(pid)
            else:
                out_line += ','

            # ppid
            if ppid != 0:
                out_line += ',' + str(ppid)
            else:
                out_line += ','

            # pname
            if len(pname) > 0:
                out_line += ',' + pname
                pname = ""
            else:
                out_line += ','

            # Source ip
            if len(s_ip) > 0:
                out_line += ',' + s_ip
            else:
                out_line += ','

            if len(s_port) > 0:
                out_line += ',' + s_port
            else:
                out_line += ','

            # Destination ip
            if len(d_ip) > 0:
                out_line += ',' + d_ip
            else:
                out_line += ','

            if len(d_port) > 0:
                out_line += ',' + d_port
            else:
                out_line += ','

            # 7 fields are empty for audit log
            for i in range(0, 7):
                out_line += ','

            if len(acct) > 0:
                out_line += ',' + acct
            else:
                out_line += ','

            if len(objname) > 0:
                out_line += ',' + objname
            else:
                out_line += ','

            # network direction
            if len(network_direction) > 0:
                out_line += ',' + network_direction
            else:
                out_line += ','

            # write lines out, remove adjacent duplicate entries
            if len([(i, j) for i, j in zip(out_line.split(','), pre_out_line.split(',')) if i != j]) > 1:
                matched = False
                if is_matched(out_line):
                    matched = True
                if out_line.startswith(","):
                    print("malformed!")
                if not ",,,,,,,,,,,,,,,,,,," in out_line:
                    if matched:
                        #wf.write(out_line + '-LA+\n')
                        preprocessing_lines.append('\n' + out_line.lower().replace("\\", "/") + '-LA+') #  + event_date + " " + timestamp
                    else:
                        #wf.write(out_line + '-LA-\n')
                        preprocessing_lines.append('\n' + out_line.lower().replace("\\", "/") + '-LA-') #  + event_date + " " + timestamp
                    pre_out_line = out_line
            pid = 0
            ppid = 0
            new_pid = 0
            new_ppid = 0
            pname = ""
            d_ip = ""
            d_port = ""
            s_ip = ""
            s_port = ""
            acct = ""
            objname = ""
            accesses = ""
            continue
            
        if "New Process ID:" in entry:
            if "0x" in entry:
                new_pid =  str(int(entry.split("0x")[1].split("\"")[0], 16))
                if len(new_pid) == 0:
                    print(entry)
            else:
                new_pid = str(int(entry.split()[-1].split("\"")[0]))
                if len(new_pid) == 0:
                    print(entry)

            pid = new_pid

            if new_pid not in process_parent:
                if new_ppid != 0:
                    process_parent[new_pid] = new_ppid
            new_pid = 0
            new_ppid = 0

            continue

        if "Creator Process ID:" in entry:
            if "0x" in entry:
                new_ppid = str(int(entry.split("0x")[1].split("\"")[0], 16))
                if len(new_ppid) == 0:
                    print(entry)
            else:
                new_ppid = str(int(entry.split()[-1].split("\"")[0]))
                if len(new_ppid) == 0:
                    print(entry)

            ppid = new_ppid

            continue

        # process id
        if "Process ID:" in entry:
            if "0x" in entry:
                pid = str(int(entry.split("0x")[1].split("\"")[0], 16))
                if len(pid) == 0:
                    print(entry)
            else:
                pid = str(int(entry.split()[-1].split("\"")[0]))
                if len(pid) == 0:
                    print(entry)
            continue

        # Process Name
        if "Application Name:" in entry or "Process Name:" in entry or "New Process Name:" in entry:
            if len(pname) == 0:
                pname = entry.split("Name:")[1]
                first_char_index = len(pname) - len(pname.lstrip())
                pname = pname[first_char_index:]
                #'''
                last_char_index = len(pname.rstrip())
                pname = pname[:last_char_index]
                
                if "\"" in pname:
                	pname = pname[:len(pname)-1]
            continue

        # destination ip
        if "Destination Address:" in entry:
            d_ip = entry.split()[-1].split("\"")[0]
            continue

        # destination port
        if "Destination Port:" in entry:
            d_port = entry.split()[-1].split("\"")[0]
            continue

        # source ip
        if "Source Address:" in entry:
            s_ip = entry.split()[-1].split("\"")[0]
            continue

        # source port
        if "Source Port:" in entry:
            s_port = entry.split()[-1].split("\"")[0]
            continue

        # principle of object access
        if "Object Type:" in entry:
            acct = entry.split()[-1].split("\"")[0]
            if len(accesses) > 0:
            	acct += accesses
            continue

        # network direction
        if "Direction:" in entry:
            network_direction = entry.split()[-1].split("\"")[0]
            continue

        # object name
        if "Object Name:" in entry:
            objname = entry.split("Object Name:")[1].lstrip().rstrip().split("\"")[0]
            continue

        if entry.startswith("Accesses:"):
            accesses = entry.split("Accesses:")[1]
            continue

# preprocess audit log
def pp_audit(wf, path):
    global preprocessing_lines
    log_file_path = path + '/audit.interpret.log'
    all_lines = []

    # first make every log entry a single line
    with open(log_file_path, 'r') as f:
        # f.next()  # skip first ----
        f.readline()
        single_lines = []
        single_line = []
        for line in f:
            line = line.strip().replace('\'', '')
            if line == '----':
                single_lines.append(' '.join(single_line))
                single_line = []
                continue
            single_line.append(line)

    # then for each log entry, compute domain
    pre_out_line = ',' * 19
    for entry in single_lines:
        out_line = ''
    
        event_date = re.findall(r'([0-9]+/[0-9]+/[0-9]+)', entry)[0]
        month, day, year = event_date.split('/')
        day_of_year = datetime(int(year), int(month), int(day)).timetuple().tm_yday
        date_val = str(int(day_of_year) * 24 * 60 * 60)
    
        # timestamp
        timestamp = re.findall(r'([0-9]+:[0-9]+:[0-9]+)\.', entry)[0]
        h, m, s = timestamp.split(':')
        out_line += str(int(h) * 3600 + int(m) * 60 + int(s) + int(date_val)).zfill(20) + "a"
    
        # queried domain
        out_line += ','
    
        # resolved ip
        out_line += ','
    
        # process id
        pid = re.findall(r' pid=([0-9]+) ', entry)
        if pid:
            out_line += ',' + pid[0]
        else:
            out_line += ','
    
        # parent process id
        ppid = re.findall(r' ppid=([0-9]+) ', entry)
        if ppid:
            out_line += ',' + ppid[0]
        else:
            out_line += ','
    
        # # process name
        # pname = re.findall(r' proctitle=(\S+) ', entry)
        # if pname:
        #     out_line += ',' + pname[0].split('/')[-1]
        # else:
        #     out_line += ','
    
        # process name
        pname = re.findall(r' exe=(\S+) ', entry)
    
        if pname:
            out_line += ',' + pname[0]
        else:
            out_line += ','
    
        # destination ip
        d_ip = re.findall(r' host:([0-9]+(?:\.[0-9]+){3}) ', entry)

        # src ip&port
        if d_ip:
            out_line += ',NO_SIP'
            out_line += ',NO_SPORT'
        else:
            out_line += ','
            # host port
            out_line += ','
    
        
        if d_ip:
            out_line += ',' + d_ip[0]
        else:
            out_line += ','
    
        # destination port
        d_port = re.findall(r' serv:([0-9]+) ', entry)
        if d_port:
            out_line += ',' + d_port[0]
        else:
            out_line += ','
    
        # 7 fields are empty for audit log
        for i in range(0, 7):
            out_line += ','
    
        # # object_access_type
        # acct = re.findall(r' nametype=(\S+) ', entry)
        # if acct:
        #     out_line += ',' + acct[0]
        # else:
        #     out_line += ','
    
        # object_access_type
        type_val = re.findall(r' type=(\S+)', entry) #[0].lower()
        nametype_val = re.findall(r' nametype=(\S+) ', entry)
        syscall_val = re.findall(r' syscall=(\S+) ', entry)
        file_accesses = ""

        if syscall_val:
            if "openat" in syscall_val[0].lower():
                a2_val = re.findall(r' a2=(\S+) ', entry)
                if a2_val:

                    if "RDONLY" in a2_val[0]:
                        file_accesses += "readdata_"
                    if "WRONLY" in a2_val[0]:
                        file_accesses += "write_"
                    if "RDWR" in a2_val[0]:
                        file_accesses += "readdata_write_"
            elif "open" in syscall_val[0].lower():
                a1_val = re.findall(r' a1=(\S+) ', entry)
                if a1_val:
                    if "RDONLY" in a1_val[0]:
                        file_accesses += "readdata_"
                    if "WRONLY" in a1_val[0]:
                        file_accesses += "write_"
                    if "RDWR" in a1_val[0]:
                        file_accesses += "readdata_write_"
            if "remove" in syscall_val[0].lower():
                file_accesses += "delete_"
            if "exec" in syscall_val[0].lower():
                file_accesses += "execute_"

        if len(file_accesses) > 0:
            out_line += ',file_' + file_accesses
        else:
            out_line += ','
        
        objname = ""
        if syscall_val:
            if "open" in syscall_val[0].lower():
                objname = re.findall(r' name=(\S+) ', entry)
            if "remove" in syscall_val[0].lower():
                objname = re.findall(r' a0=(\S+) ', entry)
            if "exec" in syscall_val[0].lower():
                objname = re.findall(r' a0=(\S+) ', entry)

        if objname:
            out_line += ',' + objname[0] #.split('/')[-1]
        else:
            out_line += ','
    
        # authentication info
        out_line += ','
    
        # write lines out, remove adjacent duplicate entries
        if len([(i, j) for i, j in zip(out_line.split(','), pre_out_line.split(',')) if i != j]) > 1:
            if is_matched(out_line):
                #wf.write('\n' + out_line + '-LA+') #  + event_date + " " + timestamp
                preprocessing_lines.append('\n' + out_line.lower().replace("\\", "/") + '-LA+') #  + event_date + " " + timestamp
            else:
                #wf.write('\n' + out_line + '-LA-') #  + event_date + " " + timestamp
                preprocessing_lines.append('\n' + out_line.lower().replace("\\", "/") + '-LA-') #  + event_date + " " + timestamp
            pre_out_line = out_line


# preprocess http log
def pp_http(wf, path):
    global preprocessing_lines

    log_file_path = path + '/firefox.txt'
    event_number = 1

    with open(log_file_path, 'r') as f:
        single_lines = []
        single_line = ''
        enter = False
        for line in f:
            if "uri=http" in line:
                single_lines.append(line)
                continue

            line = line.strip().replace('\'', '').replace('\"', '')
            if 'http response [' in line or 'http request [' in line:
                enter = True
                single_line += line
                continue

            if enter:
                if ' ]' not in line:
                    single_line += ' ' + line
                else:
                    enter = False
                    single_lines.append(single_line)
                    single_line = ''

    # then for each log entry, compute domain
    pre_out_line = ',' * 19
    for entry in single_lines:
        out_line = ''

        # timestamp
        timestamp = re.findall(r'([0-9]+:[0-9]+:[0-9]+)\.', entry)[0]
        h, m, s = timestamp.split(':')

        event_date = entry.split()[0]
        year, month, day = event_date.split('-')
        day_of_year = datetime(int(year), int(month), int(day)).timetuple().tm_yday
        if 0 <= int(h) <= 3:
            h = str(24 + int(h) + (ADJ_FF_TIME))
            day_of_year = day_of_year - 1
            timestamp = h + ":" + m + ":" + s
            event_date = "2018-" + str(date.fromordinal(day_of_year).timetuple().tm_mon) + "-" + str(date.fromordinal(day_of_year).timetuple().tm_mday)
        else:
            h = str(int(h) + (ADJ_FF_TIME))

        date_val = str(int(day_of_year) * 24 * 60 * 60)

        out_line += str(int(h) * 3600 + int(m) * 60 + int(s) + int(date_val)).zfill(20) + "c" + str(event_number) # str((int(h) + 3) * 3600 + int(m) * 60 + int(s))
        event_number += 1

        for i in range(0, 9):
            out_line += ','

        # http type
        if "uri=http" in entry:
            out_line += ',' + "request"
        else:
            type = re.findall(r' http (\S+) \[', entry)
            if type:
                out_line += ',' + type[0]
            else:
                out_line += ','
        url = ""
        # get query
        if "uri=http" in entry and "://" in entry:
            url = entry.split("://")[1]
            #url_trim = url[url.find("/"):]
            url_trim = url
            if len(url_trim) > 0:
                url_trim = url_trim.split()[0]
                if url_trim:
                    if url_trim.endswith("]"):
                        url_trim = url_trim.split("]")[0]
                out_line += ',' + url_trim.replace(',', '')
            else:
                out_line += ','
        else:
            get_q = re.findall(r' GET (\S+) HTTP', entry)
            if get_q:
                #get_q = get_q[0][get_q[0].find("/"):]
                get_q = get_q[0][:]
                if get_q.endswith("]"):
                    get_q = get_q.split("]")[0]
                if get_q.startswith("/"):
                    continue # redundant event
                out_line += ',' + get_q.replace(',', '')
            else:
                out_line += ','

        # post query
        post_q = re.findall(r' POST (\S+) HTTP', entry)
        if post_q:
            post_q = post_q[0][post_q[0].find("/"):]
            if post_q.endswith("]"):
                post_q = post_q.split("]")[0]
            out_line += ',' + post_q.replace(',', '')
        else:
            out_line += ','

        # response code
        res_code = re.findall(r' HTTP/[0-9]\.[0-9] ([0-9]+) ', entry)
        if res_code:
            out_line += ',' + res_code[0]
        else:
            out_line += ','

        # 14- host domain name, if request, if response?
        if " Host: " in entry:
            h_domain = re.findall(r' Host: (.*?) ', entry)
            if h_domain:
                h_domain = h_domain[0]
                if ":" in h_domain:
                    h_domain = h_domain.split(":")[0]
                out_line += ',' + h_domain
            else:
                out_line += ','
        else:
            res_loc = re.findall(r' Location: (.*?) ', entry)
            if res_loc:
                host = ""
                loc_url = res_loc[0]
                if loc_url:
                    if loc_url.endswith("]"):
                        loc_url = loc_url.split("]")[0]
                if "://" in loc_url:
                    host = loc_url.split("://")[1]
                    host = host.split("/")[0]
                    if ":" in host:
                        host = host.split(":")[0]
                    out_line += ',' + host
            else:
                out_line += ','

        # 15- referer
        referer = re.findall(r' Referer: (.*?) ', entry)
        if referer:
            referer = referer[0]
            if "://" in referer:
                referer = referer.split("://")[1]
            if referer.endswith("/"):
                referer = referer[:len(referer)-1]
            out_line += ',' + referer.replace(',', '')
        else:
            out_line += ','

        # 16- location of redirect
        res_loc = re.findall(r' Location: (.*?) ', entry)
        if res_loc:
            res_loc = res_loc[0]
            if "://" in res_loc:
                res_loc = res_loc.split("://")[1]
            if res_loc.endswith("/"):
                res_loc = res_loc[:len(res_loc)-1]
            out_line += ',' + res_loc.replace(',', '')
        else:
            out_line += ','

        for i in range(0, 3):
            out_line += ','

        # write lines out, remove adjacent duplicate entries
        if len([(i, j) for i, j in zip(out_line.split(','), pre_out_line.split(',')) if i != j]) > 1:
            matched = False
            if "/RiPleEsZw/PjttGs/ZIUgsQ.swf" in entry:
                print(entry)
            if is_matched(out_line):
                matched = True
            if not ",,,,,,,,,,,,,,,,,,," in out_line:
                if matched:
                    #wf.write(out_line + '-LB+\n')
                    preprocessing_lines.append('\n' + out_line.lower().replace("\\", "/") + '-LB+') #  + event_date + " " + timestamp
                else:
                    #wf.write(out_line + '-LB-\n')
                    preprocessing_lines.append('\n' + out_line.lower().replace("\\", "/") + '-LB-') #  + event_date + " " + timestamp
                pre_out_line = out_line

if __name__ == '__main__':
    # '''
    for file in os.listdir("training_logs"): 
        print("parsing: training_logs/" + file)
        preprocessing_lines = []
        path = os.path.join("training_logs", file + "/logs")
        mlabels_file = open("training_logs" + "/" + file + "/malicious_labels.txt")
        malicious_labels = mlabels_file.readlines()
        malicious_labels = [x.strip() for x in malicious_labels] 
        print("\nMalicious entities:")
        print(str(malicious_labels) + "\n")
        output_file = "output/training_preprocessed_logs_" + file
        training_wf = open(output_file, 'w')
        if "linux" in file:
            pp_audit(training_wf, path)
        if "windows" in file:
            pp_dns(training_wf, path)
            pp_http(training_wf, path)
            pp_audit_w(training_wf, path)
        order_events()
        training_wf.writelines(preprocessing_lines)
    # '''

    for file in os.listdir("testing_logs"):
        print("parsing: testing_logs/" + file)
        preprocessing_lines = []
        path = os.path.join("testing_logs", file + "/logs")
        mlabels_file = open("testing_logs" + "/" + file + "/malicious_labels.txt")
        malicious_labels = mlabels_file.readlines()
        malicious_labels = [x.strip() for x in malicious_labels]
        print("\nMalicious entities:")
        print(str(malicious_labels) + "\n")
        output_file = "output/testing_preprocessed_logs_" + file
        testing_wf = open(output_file, 'w')
        if "linux" in file:
            pp_audit(testing_wf, path)
        if "windows" in file:
            pp_dns(testing_wf, path)
            pp_http(testing_wf, path)
            pp_audit_w(testing_wf, path)
        order_events()
        testing_wf.writelines(preprocessing_lines)
        '''
        preprocessing_lines.sort()
        for i in range(0, len(preprocessing_lines)):
            node = preprocessing_lines[i]
            preprocessing_lines[i] = str(int(node[:node.find(',')-1])) + node[node.find(','):] + "\n"
        testing_wf.writelines(preprocessing_lines)
        '''
