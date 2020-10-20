# precision-recall curve and f1
from sklearn.datasets import make_classification
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import precision_recall_curve
from sklearn.metrics import f1_score
from sklearn.metrics import auc
from sklearn.metrics import roc_curve
from sklearn.metrics import roc_auc_score
from matplotlib import pyplot
import json
import numpy as np
import os
import re 
from random import randrange

def calculate_output(testy, lines_testy, normal_lines, yhat, lines_yhat, fp, fn, augmented_predicted_words, augmented_predicted_words_max_prob, augmented_lr_probs, lines_lr_probs, lines_fp, lines_fn, all_words_unique, unique_malicious_counter, g_attacks_names):
	processes_executed = 0
	files_operated = 0
	domain_names_queried = 0
	ip_addreses_communicated = 0
	sockets_send_recv_counted = 0
	urls_counted = 0

	for c in list(normal_lines["processes"]):
		processes_executed += normal_lines["processes"][c]
	for c in list(normal_lines["files"]):
		files_operated += normal_lines["files"][c]
	for c in list(normal_lines["domain_names"]):
		domain_names_queried += normal_lines["domain_names"][c]
	for c in list(normal_lines["ip_addreses"]):
		ip_addreses_communicated += normal_lines["ip_addreses"][c]
	for c in list(normal_lines["sockets_send_recv"]):
		sockets_send_recv_counted += normal_lines["sockets_send_recv"][c]
	for c in list(normal_lines["urls"]):
		urls_counted += normal_lines["urls"][c]

	ns_probs = [0 for _ in range(len(testy))]
	lines_ns_probs = [0 for _ in range(len(lines_testy))]

	lr_precision, lr_recall, _ = precision_recall_curve(testy, augmented_lr_probs)
	lines_lr_precision, lines_lr_recall, _ = precision_recall_curve(lines_testy, lines_lr_probs)

	ns_fpr, ns_tpr, _ = roc_curve(testy, ns_probs)
	lines_ns_fpr, lines_ns_tpr, _ = roc_curve(lines_testy, lines_ns_probs)

	lr_fpr, lr_tpr, _ = roc_curve(testy, augmented_lr_probs)
	lines_lr_fpr, lines_lr_tpr, _ = roc_curve(lines_testy, lines_lr_probs)

	lr_f1, lr_auc = f1_score(testy, yhat), auc(lr_recall, lr_precision)
	lines_lr_f1, lines_lr_auc = f1_score(lines_testy, lines_yhat), auc(lines_lr_recall, lines_lr_precision)
	
	ns_auc = roc_auc_score(testy, ns_probs)
	lines_ns_auc = roc_auc_score(lines_testy, lines_ns_probs)

	lr_auc = roc_auc_score(testy, augmented_lr_probs)
	lines_lr_auc = roc_auc_score(lines_testy, lines_lr_probs)

	# plot the precision-recall curves
	no_skill = len(testy[testy==1]) / len(testy)

	pyplot.plot([0, 1], [no_skill, no_skill], linestyle='--', label='No Skill')
	pyplot.plot(lr_recall, lr_precision, marker='.', linestyle='dotted', label='Logistic')
	pyplot.plot(lr_recall, marker='.', linestyle='dotted', label='Recall')
	pyplot.plot(lr_precision, marker='.', linestyle='dotted', label='Precision')
	# axis labels
	pyplot.xlabel('Recall')
	pyplot.ylabel('Precision')
	# configure grid
	pyplot.grid(axis='y', color='0.95')
	# show the legend
	pyplot.legend()
	# show the plot
	# pyplot.show()		

	# plot the precision-recall curves
	lines_no_skill = len(lines_testy[lines_testy==1]) / len(lines_testy)
	pyplot.plot([0, 1], [lines_no_skill, lines_no_skill], linestyle='--', label='No Skill')
	pyplot.plot(lines_lr_recall, lines_lr_precision, marker='.', linestyle='dotted', label='Logistic')
	# axis labels
	pyplot.xlabel('Recall')
	pyplot.ylabel('Precision')
	# configure grid
	pyplot.grid(axis='y', color='0.95')
	# show the legend
	pyplot.legend()
	# show the plot
	# pyplot.show()		

	# plot the roc curve for the model
	pyplot.plot(ns_fpr, ns_tpr, linestyle='--', label='No Skill')
	pyplot.plot(lr_fpr, lr_tpr, marker='.', label='Logistic')
	# axis labels
	pyplot.xlabel('False Positive Rate')
	pyplot.ylabel('True Positive Rate')
	# show the legend
	pyplot.legend()
	# show the plot
	# pyplot.show()

	# plot the roc curve for the model
	pyplot.plot(lines_ns_fpr, lines_ns_tpr, linestyle='--', label='No Skill')
	pyplot.plot(lines_lr_fpr, lines_lr_tpr, marker='.', label='Logistic')
	# axis labels
	pyplot.xlabel('False Positive Rate')
	pyplot.ylabel('True Positive Rate')
	# show the legend
	pyplot.legend()
	# show the plot
	# pyplot.show()

	# attack_name = "A-" + str(randrange(99999))
	attack_name = ""
	first_iteration = True
	for a in g_attacks_names:
		if first_iteration:
			first_iteration = False
		else:
			 attack_name += ";"
		attack_name += a

	file_name = 'output/plot_data_' + attack_name + '.json'
	plot_file = open(file_name, 'w')
	print("wrote plot data to :" + file_name)
	json.dump([attack_name, lr_recall.tolist(), lr_precision.tolist(), lines_lr_recall.tolist(), lines_lr_precision.tolist(), no_skill, lines_no_skill, ns_fpr.tolist(), ns_tpr.tolist(), lr_fpr.tolist(), lr_tpr.tolist(), lines_ns_fpr.tolist(), lines_ns_tpr.tolist(), lines_lr_fpr.tolist(), lines_lr_tpr.tolist()], plot_file)
	
	# summarize scores
	# print('Entities: auc=%.3f' % (lr_auc))
	# print('Events: auc=%.3f' % (lines_lr_auc))
	# print('Entities: f1=%.3f auc=%.3f' % (lr_f1, lr_auc))
	# print('Events: f1=%.3f auc=%.3f' % (lines_lr_f1, lines_lr_auc))
	print('No Skill: ROC AUC=%.4f' % (ns_auc))
	print('Logistic: ROC AUC=%.4f' % (lr_auc))
	print('Lines No Skill: ROC AUC=%.4f' % (lines_ns_auc))
	print('Lines Logistic: ROC AUC=%.4f' % (lines_lr_auc))

	print("Number of normal unique processes: " + str(len(list(normal_lines["processes"]))))
	print("Number of normal unique files: " + str(len(list(normal_lines["files"]))))
	print("Number of normal unique domain_names: " + str(len(list(normal_lines["domain_names"]))))
	print("Number of normal unique ip_addreses: " + str(len(list(normal_lines["ip_addreses"]))))
	print("Number of normal unique sockets_send_recv: " + str(len(list(normal_lines["sockets_send_recv"]))))
	print("Number of normal unique urls: " + str(len(list(normal_lines["urls"]))))

	print("Number of normal processes triggers: " + str(processes_executed))
	print("Number of normal files accessed: " + str(files_operated))
	print("Number of normal domain names queried: " + str(domain_names_queried))
	print("Number of normal ip_addreses connected: " + str(ip_addreses_communicated))
	print("Number of normal sockets_send_recv triggered: " + str(sockets_send_recv_counted))
	print("Number of normal urls requested: " + str(urls_counted))
	
	print("\n## Info (entity) ##")
	print("Number of unique entities: " + str(len(all_words_unique)))
	print("Number of malicious entities: " + str(unique_malicious_counter))
	print("## Result (entity) ##")
	tp = unique_malicious_counter - fn
	tn = (len(all_words_unique)-unique_malicious_counter) - fp
	precision = float(tp/(tp+fp))
	recall = float(tp/(tp+fn))
	f1_s = 2 * ((precision*recall)/(precision+recall))
	print("TP: " + str(tp))
	print("TN: " + str(tn))
	print("FP: " + str(fp))
	print("FN: " + str(fn))
	# print("Precision: " + str(precision))
	# print("Recall: " + str(recall))
	# print("F1-score: " + str(f1_s))


	print("\n## Info (event) ##")
	print("Number of events: " + str(lines_testy.size))
	print("Number of malicious events: " + str(int(np.sum(lines_testy))))
	print("## Result (event) ##")
	tp_lines = int(np.sum(lines_testy)) - lines_fn
	tn_lines = (lines_testy.size-int(np.sum(lines_testy))) - lines_fp
	precision_lines = float(tp_lines/(tp_lines+lines_fn))
	recall_lines = float(tp_lines/(tp_lines+lines_fp))
	f1_s_lines = 2 * ((precision_lines*recall_lines)/(precision_lines+recall_lines))
	print("TP: " + str(tp_lines))
	print("TN: " + str(tn_lines))
	print("FP: " + str(lines_fp))
	print("FN: " + str(lines_fn))
	# print("Precision: " + str(precision_lines))
	# print("Recall: " + str(recall_lines))
	# print("F1-score: " + str(f1_s_lines))

augmented_predicted_words = {}
augmented_predicted_words_max_prob = {}


def is_number(str): 
    return bool(re.search(r'^[0-9]+$', str) )

def collect_max_prob(file):
	global augmented_predicted_words, augmented_predicted_words_max_prob
	data_text = ""

	f = open(file, 'r')
	print("read from : " + file)
	data_text = f.read()

	data = json.loads(data_text)

	cleaned_predicted_words = data[0]
	malicious_words = data[1]
	attack_clue = data[2]
	all_words = data[3]
	all_words_prediction = data[4]
	lr_probs = np.array(data[5])
	lines = data[6]
	dataset_name = data[7]

	if len(cleaned_predicted_words) == 0:
		print("ERROR: Please add the cleaned predicted entities for abstracted and raw logs.")
		exit()

	# print(lr_probs)

	for w in cleaned_predicted_words:
		if not w in list(augmented_predicted_words):
			augmented_predicted_words[w] = []

	for i in range(0, len(all_words)):
		for m in cleaned_predicted_words:
			if m in all_words[i]:
				augmented_predicted_words[m].append((all_words[i], lr_probs[i]))
				break

	clue_proba = 1.0
	first_iter = True

	for k in augmented_predicted_words.keys():
		max_prob = 0

		if first_iter:
			max_prob = clue_proba
			first_iter = False

		for t in augmented_predicted_words[k]:
			if t[1] > max_prob:
				max_prob = t[1]
				
		augmented_predicted_words_max_prob[k] = max_prob

	# print("-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-")
	# print(augmented_predicted_words)
	# print("-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-")

	tmp_prob = {}
	for k in augmented_predicted_words_max_prob.keys():
		if augmented_predicted_words_max_prob[k] < 0.5:
			continue
		if "_" in k:
			splitted_str = k.split("_")
			if len(splitted_str) >= 1:
				if is_number(splitted_str[-1]):
					process_id = splitted_str[-1]
					for kk in augmented_predicted_words_max_prob.keys():
						if k == kk or augmented_predicted_words_max_prob[kk] > 0.5:
							continue
						if "," in kk:
							splitted_str2 = kk.split(",")
							if len(splitted_str2) >= 2:
								if is_number(splitted_str2[1]):
									if splitted_str2[1] == process_id:
										augmented_predicted_words_max_prob[kk] = augmented_predicted_words_max_prob[k]

	print("-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-")
	print("Cleaned predicted entities: ")
	print(augmented_predicted_words_max_prob)
	print("-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-")
	
files_counter = 0
def process_file(file):
	global augmented_predicted_words, augmented_predicted_words_max_prob, files_counter
	data_text = ""
	files_counter += 1

	f = open(file, 'r')
	print("read from : " + file)
	data_text = f.read()

	data = json.loads(data_text)

	cleaned_predicted_words = data[0]
	malicious_words = data[1]
	attack_clue = data[2]
	all_words = data[3]
	all_words_prediction = data[4]
	lr_probs = np.array(data[5])
	lines = data[6]
	dataset_name = data[7]

	if len(cleaned_predicted_words) == 0:
		print("ERROR: Please add the cleaned predicted entities for abstracted and raw logs.")
		exit()

	testy = []
	
	for w in all_words:
		MATCH = False
		for m in malicious_words:
			if m in w:
				MATCH = True
				testy.append(1)
				break
		if not MATCH:
			testy.append(0)

	testy = np.array(testy)

	lines_testy = []
	normal_lines = {}
	normal_lines["processes"] = {}
	normal_lines["files"] = {}
	normal_lines["domain_names"] = {} 
	normal_lines["ip_addreses"] = {} 
	normal_lines["sockets_send_recv"] = {} 
	normal_lines["urls"] = {} 

	for l in lines:
		MATCH = False
		for m in malicious_words:
			if m in l:
				MATCH = True
				lines_testy.append(1)
				break
		if not MATCH:
			element = l.split(',')
			for i in range(0, len(element)):
				if  len(element[i]) > 0:
					current_element = "h" + str(files_counter) + "_" + element[i]
					if i == 4:
						if not current_element in list(normal_lines["processes"]):
							normal_lines["processes"][current_element] = 1
						else:
							normal_lines["processes"][current_element] += 1
					if i == 18:
						if not current_element in list(normal_lines["files"]):
							normal_lines["files"][current_element] = 1
						else:
							normal_lines["files"][current_element] += 1
					if i == 1:
						if not current_element in list(normal_lines["domain_names"]):
							normal_lines["domain_names"][current_element] = 1
						else:
							normal_lines["domain_names"][current_element] += 1
					if i == 2 or i == 6 or i == 8:
						if not current_element in list(normal_lines["ip_addreses"]):
							normal_lines["ip_addreses"][current_element] = 1
						else:
							normal_lines["ip_addreses"][current_element] += 1
					if i == 6:
						socket = ""
						if len(current_element) > 0 and len(element[i+1]) > 0 and len(element[i+2]) > 0 and len(element[i+3]) > 0:
							socket = str(current_element) + "_" + str(element[i+1]) + "_"  + str(element[i+2]) + "_"  + str(element[i+3])

						if not current_element in list(normal_lines["sockets_send_recv"]):
							normal_lines["sockets_send_recv"][socket] = 1
						else:
							normal_lines["sockets_send_recv"][socket] += 1
					if i == 11:
						if not current_element in list(normal_lines["urls"]):
							normal_lines["urls"][current_element] = 1
						else:
							normal_lines["urls"][current_element] += 1
					
			lines_testy.append(0)

	
	lines_testy = np.array(lines_testy)

	all_words_unique = list(set(all_words))
	unique_malicious_counter = 0
	for w in all_words_unique:
		for m in malicious_words:
			if m in w:
				unique_malicious_counter += 1
				break

	yhat = []
	fp = 0
	fn = 0
	counter = 0
	fp_list = []
	fn_list = []

	for w in all_words:
		MATCH = False
		for m in cleaned_predicted_words:
			if m in w:
				MATCH = True
				yhat.append(1)
				if testy[counter] == 0:
					if not w in fp_list:
						fp += 1
						fp_list.append(w)
					# print("entities_FP: " + w)
				break
		if not MATCH:
			yhat.append(0)
			if testy[counter] == 1:
				if not w in fn_list:
					fn += 1
					fn_list.append(w)
				# print("entities_FN: " + w)

		counter += 1

	yhat = np.array(yhat)

	lines_yhat = []
	lines_fp = 0
	lines_fn = 0
	counter = 0
	fp_list_lines = []
	fn_list_lines = []
	
	for l in lines:
		MATCH = False
		for m in cleaned_predicted_words:
			if m in l:
				MATCH = True
				lines_yhat.append(1)
				if lines_testy[counter] == 0:
					if not l in fp_list_lines:
						lines_fp += 1
						fp_list_lines.append(l)
					# print("Lines_FP: " + l)
				break
		if not MATCH:
			lines_yhat.append(0)
			if lines_testy[counter] == 1:
				if not l in fn_list_lines:
					lines_fn += 1
					fn_list_lines.append(l)
				# print("Lines_FN: " + l)
		counter += 1


	lines_yhat = np.array(lines_yhat)

	augmented_lr_probs = lr_probs

	for i in range(0, len(all_words)):
		MATCH = False
		for m in cleaned_predicted_words:
			if m in all_words[i]:
				if m in augmented_predicted_words_max_prob.keys():
					augmented_lr_probs[i] = augmented_predicted_words_max_prob[m]
					# None

	# print("*******************")
	# print(augmented_predicted_words_max_prob)
	lines_lr_probs = np.zeros(len(lines))

	for l in range(0, len(lines)):
		MATCH = False
		if lines_yhat[l] == 1:
			for m in cleaned_predicted_words:
				if m in lines[l]:
					if m in augmented_predicted_words_max_prob.keys():
						lines_lr_probs[l] = augmented_predicted_words_max_prob[m]
						# None
						MATCH = True
						break
			if MATCH:
				continue
			else:
				print("Error: Predicted as attack but couldn't find the probability!!")
				continue
		elif lines_yhat[l] == 0:
			for substr in lines[l].split(','):
				# count for mis-parsed words
				if len(substr) >= 5:
					for w in range(0, len(all_words)):
						if substr in all_words[w]:
							lines_lr_probs[l] = lr_probs[w]
							MATCH = True
							break
					if MATCH:
						break
			if not MATCH:
				# print("Error: Predicted as normal but couldn't find the probability!!")
				continue

	return testy, lines_testy, normal_lines, yhat, lines_yhat, fp, fn, augmented_predicted_words, augmented_predicted_words_max_prob, augmented_lr_probs, lines_lr_probs, lines_fp, lines_fn, all_words_unique, unique_malicious_counter, dataset_name

	

directory = "output/"
for file in os.listdir(directory):
	if file.startswith("eval_"):
		collect_max_prob(directory + file)

result = {}
for file in os.listdir(directory):
	if file.startswith("eval_"):
		result[file] = process_file(directory + file)

g_testy = np.array([])
g_lines_testy = np.array([])
g_normal_lines = {}
g_normal_lines["processes"] = {}
g_normal_lines["files"] = {} 
g_normal_lines["domain_names"] = {} 
g_normal_lines["ip_addreses"] = {} 
g_normal_lines["sockets_send_recv"] = {}
g_normal_lines["urls"] = {}
g_yhat = np.array([])
g_lines_yhat = np.array([])
g_fp = 0
g_fn = 0
g_augmented_predicted_words = []
g_augmented_predicted_words_max_prob = []
g_augmented_lr_probs = np.array([])
g_lines_lr_probs = np.array([])
g_lines_fp = 0
g_lines_fn = 0
g_all_words_unique = []
g_unique_malicious_counter = 0
g_attacks_names = []

for k in list(result):
	values_list = result[k]

	g_testy = np.append(g_testy, values_list[0])
	g_lines_testy = np.append(g_lines_testy, values_list[1])
	for kk in list(values_list[2]):
		g_normal_lines[kk].update(values_list[2][kk])
	g_yhat = np.append(g_yhat, values_list[3])
	g_lines_yhat = np.append(g_lines_yhat, values_list[4])
	g_fp += values_list[5]
	g_fn += values_list[6]
	g_augmented_predicted_words += values_list[7]
	g_augmented_predicted_words_max_prob += values_list[8]
	g_augmented_lr_probs = np.append(g_augmented_lr_probs, values_list[9])
	g_lines_lr_probs = np.append(g_lines_lr_probs, values_list[10])
	g_lines_fp += values_list[11]
	g_lines_fn += values_list[12]
	g_all_words_unique += values_list[13]
	g_unique_malicious_counter += values_list[14]
	g_attacks_names.append(values_list[15])

calculate_output(g_testy, g_lines_testy, g_normal_lines, g_yhat, g_lines_yhat, g_fp, g_fn, g_augmented_predicted_words, g_augmented_predicted_words_max_prob, g_augmented_lr_probs, g_lines_lr_probs, g_lines_fp, g_lines_fn, g_all_words_unique, g_unique_malicious_counter, g_attacks_names)


