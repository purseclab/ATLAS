from networkx.drawing.nx_pydot import read_dot
import os
import time

# NOTE: If you are getting this error: 
# TypeError: can only concatenate str (not "ParseException") to str
# Then fix by going to C:\**\Python37\Lib\site-packages:
# change this code:
# print(
#             err.line +
#             " "*(err.column-1) + "^" +
#             err)
# To:
# print(
#             err.line +
#             " "*(err.column-1) + "^" +
#             str(err))

if __name__ == '__main__':
	for file in os.listdir("output"):
		if file.startswith("graph_training_preprocessed_logs") or file.startswith("graph_testing_preprocessed_logs"):
			#if not file.startswith("graph_training_preprocessed_logs_multicore CVE-2015-5122_windows_https_files"):
			#	continue
			start = time.time()

			written_lines = []
			path = "output/" + file
			print("\n============\nprocessing the graph: " + path)
			G = read_dot(path)
			output_file_path = "output/" + "seq_" + file + ".txt"
			
			if os.path.exists(output_file_path):
			  os.remove(output_file_path)
			
			output_file = open(output_file_path, "a")
			
			for a, b, data in sorted(G.edges(data=True), key=lambda x: x[2]['timestamp']):
				op_type = data['type']
				#  or op_type == "connect" op_type == "read" or op_type == "executed" 
				if op_type == "bind" or op_type == "sock_send" or op_type == "connect" or op_type == "write" or op_type == "delete" or op_type == "fork" or op_type == "resolve" or op_type == "web_request" or op_type == "refer":
					formatted_str = '{b} {w} {a}\n'.format(a=a.lstrip().rstrip().replace(" ", ""), w=op_type, b=b.lstrip().rstrip().replace(" ", ""))
					if not formatted_str in written_lines:
						output_file.write(formatted_str)
						written_lines.append(formatted_str)
				else:
					formatted_str = '{a} {w} {b}\n'.format(a=a.lstrip().rstrip().replace(" ", ""), w=op_type, b=b.lstrip().rstrip().replace(" ", ""))
					if not formatted_str in written_lines:
						output_file.write(formatted_str)
						written_lines.append(formatted_str)

			done = time.time()
			elapsed = done - start
			print("processing time: " + str(elapsed))
			
			print("The graph has been turned into sequence of events, output saved to " + output_file_path)			
