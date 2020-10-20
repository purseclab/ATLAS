import numpy as np
seed = 1337
np.random.seed(seed)

import sys
import os
import json
from fuzzywuzzy import fuzz
from itertools import combinations
import h5py
import random
from keras.models import model_from_json
from keras.preprocessing import sequence
from keras.models import Sequential
from keras.models import load_model
from keras.layers import Dense, Dropout, Embedding, LSTM, Bidirectional, GRU
from sklearn.preprocessing import StandardScaler
from matplotlib import pyplot
import matplotlib.pyplot as plt
from keras import layers
import keras
from keras.layers import Conv1D, GlobalAveragePooling1D, MaxPooling1D
from keras.preprocessing import sequence
from keras.models import Sequential
from keras.layers import Dense, Dropout, Activation
from keras.layers import Embedding
from keras.layers import Conv1D, GlobalMaxPooling1D
from keras.datasets import imdb
from numpy import array
from keras.optimizers import RMSprop
from scipy.sparse import coo_matrix
from sklearn.utils import shuffle
from keras.models import Model
from keras.layers import Input, Dense, Dropout, Flatten
from keras.layers.convolutional import Convolution1D, MaxPooling1D

from keras.models import Model
from keras.layers import Input
from keras.layers import Dense
from keras.layers import Flatten
from keras.layers import Dropout
from keras.layers import Embedding
from keras.layers.convolutional import Conv1D
from keras.layers.convolutional import MaxPooling1D
from keras.layers.merge import concatenate
from keras.callbacks import EarlyStopping
from sklearn.model_selection import StratifiedKFold
from sklearn.datasets import make_classification
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import precision_recall_curve
from sklearn.metrics import f1_score
from sklearn.metrics import auc
from matplotlib import pyplot
import json
import time

prediction_counter = 0
current_file = ""
user_artifact =  ""
TESTING_STARTED = False

# Cross validation K-fold
kfold = StratifiedKFold(n_splits=6, shuffle=True, random_state=seed)
cvscores = []

batch_size = 1 
input_file_path = ""
input_file = None
mlabels_file = None
mlabels_file_events = None
malicious_labels = None
malicious_labels_events = None
tokenized_elements = {}
maxlen = 400 # cut after this number of words
x_dataset = []
y_dataset = []
z_dataset = []
x_train = []
y_train = []
z_train = []
x_test = []
y_test = []
z_test = []
mal_com_seq_list = [] # list of the malicious sequences
seen_tokenized_sequences = [] # to avoid replicating seen sequences
CUSTOM_FIT = 0 # different settings for fitting
tokenized_x_train_elements = {}


tokenized_elements["process"] = 1
tokenized_elements["file"] = 2
tokenized_elements["IP_Address"] = 3
tokenized_elements["domain_name"] = 4
tokenized_elements["web_object"] = 5
tokenized_elements["read"] = 6
tokenized_elements["write"] = 7
tokenized_elements["delete"] = 8
tokenized_elements["execute"] = 9
tokenized_elements["executed"] = 10
tokenized_elements["fork"] = 11
tokenized_elements["connect"] = 12
tokenized_elements["resolve"] = 13
tokenized_elements["web_request"] = 14
tokenized_elements["refer"] = 15
tokenized_elements["combined_files"] = 16 
tokenized_elements["windows_file"] = 17
tokenized_elements["windows_process"] = 18
tokenized_elements["system32_file"] = 19
tokenized_elements["system32_process"] = 20
tokenized_elements["programfiles_file"] = 21
tokenized_elements["programfiles_process"] = 22
tokenized_elements["user_file"] = 23
tokenized_elements["user_process"] = 24
tokenized_elements["bind"] = 25
tokenized_elements["sock_send"] = 26
tokenized_elements["connection"] = 27
tokenized_elements["connected_remote_ip"] = 28
tokenized_elements["session"] = 29
tokenized_elements["connected_session"] = 30


tokenized_x_train_elements[1] = "a"
tokenized_x_train_elements[2] = "b"
tokenized_x_train_elements[3] = "c"
tokenized_x_train_elements[4] = "d"
tokenized_x_train_elements[5] = "e"
tokenized_x_train_elements[6] = "f"
tokenized_x_train_elements[7] = "g"
tokenized_x_train_elements[8] = "h"
tokenized_x_train_elements[9] = "i"
tokenized_x_train_elements[10] = "j"
tokenized_x_train_elements[11] = "k"
tokenized_x_train_elements[12] = "l"
tokenized_x_train_elements[13] = "m"
tokenized_x_train_elements[14] = "n"
tokenized_x_train_elements[15] = "o"
tokenized_x_train_elements[16] = "p"
tokenized_x_train_elements[17] = "q"
tokenized_x_train_elements[18] = "r"
tokenized_x_train_elements[19] = "s"
tokenized_x_train_elements[20] = "t"
tokenized_x_train_elements[21] = "u"
tokenized_x_train_elements[22] = "v"
tokenized_x_train_elements[23] = "w"
tokenized_x_train_elements[24] = "x"
tokenized_x_train_elements[25] = "y"
tokenized_x_train_elements[26] = "z"
tokenized_x_train_elements[27] = "A"
tokenized_x_train_elements[28] = "B"
tokenized_x_train_elements[29] = "C"
tokenized_x_train_elements[30] = "D"

model = None
# Convolution
kernel_size = 5
filters =  64
pool_size = 8
max_features = 31 # number of features=words
embedding_size = 128 # 128 dimensions that the model learns for each word=feature
lstm_output_size = 256 
EPOCH = 8 
u_thresh = 80 
DO_TRAINING =  False # True # 
load_resampling = True # False # 
load_nonsampling = False # True # 
load_undersampling = False
SHOW_STAT = False # True # # show graphs after calling fit()
maximum_number_of_test_iterations = 1 

def generate_model():
	global model

	model = Sequential()
	model.add(Embedding(max_features, embedding_size, input_length=maxlen))
	
	model.add(Conv1D(filters, kernel_size, activation='relu'))
	model.add(MaxPooling1D(pool_size=pool_size))
	model.add(Dropout(0.2))
	model.add(LSTM(lstm_output_size))
	model.add(Dense(1, activation='sigmoid'))
	model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy']) 
	

if DO_TRAINING:
	generate_model()
else:
	print("Saved model output/model.h5 has been loaded!")
	model = load_model('output/model.h5')
	print("%s" % (model.metrics_names[1]))
	


def load_malicious_labels(file):
	global mlabels_file, mlabels_file_events, malicious_labels, malicious_labels_events

	training_prefix = "seq_graph_training_preprocessed_logs_"
	testing_prefix = "seq_graph_testing_preprocessed_logs_"
	if file.startswith(training_prefix):
		mlabels_file = open("training_logs/" + file[len(training_prefix):-8] + "/malicious_labels.txt")
		mlabels_file_events = open("training_logs/" + file[len(training_prefix):-8] + "/malicious_labels.txt")
	if file.startswith(testing_prefix):
		mlabels_file = open("testing_logs/" + file[len(testing_prefix):-8] + "/malicious_labels.txt")
		mlabels_file_events = open("testing_logs/" + file[len(testing_prefix):-8] + "/malicious_labels.txt")
	malicious_labels = mlabels_file.readlines()
	malicious_labels = [x.strip().lower() for x in malicious_labels]
	malicious_labels_events = mlabels_file_events.readlines()
	malicious_labels_events = [x.strip().lower() for x in malicious_labels_events]

def is_matched(string, labels=None):
	global malicious_labels

	if labels == None:
		labels = malicious_labels

	for label in labels:
		if label in string:
			return True
	return False


def tokenize_sequences(seq):
	seq_list = seq.split()
	
	for i in range(0, int(len(seq_list)/3)):
		if seq_list[i*3+1] == "read" or seq_list[i*3+1] == "write" or seq_list[i*3+1] == "delete" or seq_list[i*3+1] == "execute":
			if "c:/windows/system32" in seq_list[i*3]:
				seq_list[i*3] = "system32_process"
			elif "c:/windows" in seq_list[i*3]:
				seq_list[i*3] = "windows_process"
			elif "c:/programfiles" in seq_list[i*3]:
				seq_list[i*3] = "programfiles_process"
			elif "c:/users" in seq_list[i*3]:
				seq_list[i*3] = "user_process"
			else:
				seq_list[i*3] = "process"

			if not ";" in seq_list[i*3+2]:
				if "c:/windows/system32" in seq_list[i*3+2]:
					seq_list[i*3+2] = "system32_file"
				elif "c:/windows" in seq_list[i*3+2]:
					seq_list[i*3+2] = "windows_file"
				elif "c:/programfiles" in seq_list[i*3+2]:
					seq_list[i*3+2] = "programfiles_file"
				elif "c:/users" in seq_list[i*3+2]:
					seq_list[i*3+2] = "user_file"
				else:
					seq_list[i*3+2] = "file"
			else:
				seq_list[i*3+2] = "combined_files"
		elif seq_list[i*3+1] == "fork":
			if "c:/windows/system32" in seq_list[i*3]:
				seq_list[i*3] = "system32_process"
			elif "c:/windows" in seq_list[i*3]:
				seq_list[i*3] = "windows_process"
			elif "c:/programfiles" in seq_list[i*3]:
				seq_list[i*3] = "programfiles_process"
			elif "c:/users" in seq_list[i*3]:
				seq_list[i*3] = "user_process"
			else:
				seq_list[i*3] = "process"

			if "c:/windows/system32" in seq_list[i*3+2]:
				seq_list[i*3+2] = "system32_process"
			elif "c:/windows" in seq_list[i*3+2]:
				seq_list[i*3+2] = "windows_process"
			elif "c:/programfiles" in seq_list[i*3+2]:
				seq_list[i*3+2] = "programfiles_process"
			elif "c:/users" in seq_list[i*3+2]:
				seq_list[i*3+2] = "user_process"
			else:
				seq_list[i*3+2] = "process"

		elif seq_list[i*3+1] == "connect" or seq_list[i*3+1] == "bind":
			if "c:/windows/system32" in seq_list[i*3]:
				seq_list[i*3] = "system32_process"
			elif "c:/windows" in seq_list[i*3]:
				seq_list[i*3] = "windows_process"
			elif "c:/programfiles" in seq_list[i*3]:
				seq_list[i*3] = "programfiles_process"
			elif "c:/users" in seq_list[i*3]:
				seq_list[i*3] = "user_process"
			else:
				seq_list[i*3] = "process"

			if seq_list[i*3+1] == "connect":
				seq_list[i*3+2] = "connection" 
			else:
				seq_list[i*3+2] = "session"

		elif seq_list[i*3+1] == "resolve":
			seq_list[i*3] = "IP_Address"
			seq_list[i*3+2] = "domain_name"
		elif seq_list[i*3+1] == "web_request":
			seq_list[i*3] = "domain_name"
			seq_list[i*3+2] = "web_object"
		elif seq_list[i*3+1] == "refer":
			seq_list[i*3] = "web_object"
			seq_list[i*3+2] = "web_object"
		elif seq_list[i*3+1] == "executed":
			if "c:/windows/system32" in seq_list[i*3]:
				seq_list[i*3] = "system32_file"
			elif "c:/windows" in seq_list[i*3]:
				seq_list[i*3] = "windows_file"
			elif "c:/programfiles" in seq_list[i*3]:
				seq_list[i*3] = "programfiles_file"
			elif "c:/users" in seq_list[i*3]:
				seq_list[i*3] = "user_file"
			else:
				seq_list[i*3] = "file"

			if "c:/windows/system32" in seq_list[i*3+2]:
				seq_list[i*3+2] = "system32_process"
			elif "c:/windows" in seq_list[i*3+2]:
				seq_list[i*3+2] = "windows_process"
			elif "c:/programfiles" in seq_list[i*3+2]:
				seq_list[i*3+2] = "programfiles_process"
			elif "c:/users" in seq_list[i*3+2]:
				seq_list[i*3+2] = "user_process"
			else:
				seq_list[i*3+2] = "process"
		elif seq_list[i*3+1] == "sock_send":
			seq_list[i*3] = "session"
			seq_list[i*3+2] = "session"
		elif seq_list[i*3+1] == "connected_remote_ip":
			seq_list[i*3] = "IP_Address"
			if not seq_list[i*3+2].startswith("connection_"):
				if "c:/windows/system32" in seq_list[i*3+2]:
					seq_list[i*3+2] = "system32_process"
				elif "c:/windows" in seq_list[i*3+2]:
					seq_list[i*3+2] = "windows_process"
				elif "c:/programfiles" in seq_list[i*3+2]:
					seq_list[i*3+2] = "programfiles_process"
				elif "c:/users" in seq_list[i*3+2]:
					seq_list[i*3+2] = "user_process"
				else:
					seq_list[i*3+2] = "process"
			else:
				seq_list[i*3+2] = "connection"
		elif seq_list[i*3+1] == "connected_session":
			seq_list[i*3] = "IP_Address"
			seq_list[i*3+2] = "session"

	joined_seq_list = " ".join(seq_list)
	
	return joined_seq_list

def construct_seq_using_labels(lines, possible_labels):
	seq_list = []
	
	for line in lines:
		line = line.rstrip()
		for l in possible_labels:
			if l in line.split()[0] or l in line.split()[2]:
				seq_list.append(line)
				break
	
	joined_seq_list = " ".join(seq_list)
	return joined_seq_list


def suggest_ground_truth(lines, possible_labels):
	global malicious_labels, seen_tokenized_sequences, mal_com_seq_list

	matched_seq_list = []
	result_list = []
	temp = []

	mal_com_seq = ""
	mal_combo_list = []
	
	combo_list = [user_artifact]
	combo_list.extend(malicious_labels)

	CONVERGED = True
	while True:
		if len(combo_list) == 0:
			break

		for l in possible_labels:
			if l in combo_list:
				continue
			combo_branch = combo_list[:]
			combo_branch.append(l)
			combo_branch_seq = construct_seq_using_labels(lines, combo_branch)
			if len(combo_branch_seq.split()) > maxlen:
				continue
			tokenized_combo_branch_seq = tokenize_sequences(combo_branch_seq)
		
			MATCHED = False
			if not tokenized_combo_branch_seq in seen_tokenized_sequences:
				seen_tokenized_sequences.append(tokenized_combo_branch_seq)

				if tokenized_combo_branch_seq in mal_com_seq_list:
					MATCHED = True
					result_list.append((combo_branch, tokenized_combo_branch_seq, 1))
					CONVERGED = True
				if not MATCHED:
					result_list.append((combo_branch, tokenized_combo_branch_seq, 0))

		del combo_list[-1]
	return result_list


def testing_suggest_ground_truth(lines, possible_labels):
	global malicious_labels, maxlen, x_test, y_test, z_test, u_thresh, user_artifact, maximum_number_of_test_iterations
	global prediction_counter, classified_words, classified_words_prediction, classified_words_proba

	mal_com_seq_list = []
	matched_seq_list = []
	result_list = []
	temp = []
	x_test = []
	y_test = []
	z_test = []
	result_labels = {}
	result_labels[1] = [[user_artifact]]

	for r in range(1, maximum_number_of_test_iterations+1):
		for mal_combo in combinations(malicious_labels, r):
			mal_combo_list = [user_artifact]
			for i in mal_combo:
				mal_combo_list.append(i)
			mal_com_seq = construct_seq_using_labels(lines, mal_combo_list)
			tokenized_mal_com_seq = tokenize_sequences(mal_com_seq)
			if not tokenized_mal_com_seq in mal_com_seq_list:
				mal_com_seq_list.append(tokenized_mal_com_seq)

	
	CONVERGED = True
	work_list = [[user_artifact]]
	work_list_len1 = 0
	work_list_len2 = len(work_list)
	last_label  = [([user_artifact], 0.0)]
	last_work_list = []
	one_group = []
	finished_indexes = []
	grouped_labels = []

	while True:
		done_work_counter = 0
		print(work_list)
		# work_list = sorted(work_list, key = lambda x: len)	#, reverse=True
		work_list = sorted(work_list, key=len)	# python 3
		# print(list(result_labels)[0])
		# print(result_labels[1])
		if not result_labels[list(result_labels)[-1]] == last_label:
			last_label = result_labels[len(list(result_labels))]
			print("\nlast predicted labels: ")
			for k in list(result_labels):
				#print str(result_labels[k])[:8000] + " ..."
				print(str(result_labels[k]))
				print("---------")
		
		# exit()
		if prediction_counter >= maximum_number_of_test_iterations: # 1
			file_name = current_file[len("seq_graph_"):-8]
			file_path = "output/" + file_name
			ofile = open(file_path, "r")
			ofile_lines = ofile.readlines()
	
			print("Finished the testing iterations. Bye.")
	
			w_current_file = 'output/eval_' + current_file + '.json'
			with open(w_current_file, 'w') as f:
				print("wrote data to: " + w_current_file)
				classified_words_prediction = classified_words_prediction.tolist() #[:len(z_test)]
				classified_words_proba = classified_words_proba.tolist() #[:len(z_test)]
				json.dump([[], malicious_labels, user_artifact, classified_words, classified_words_prediction, classified_words_proba, ofile_lines, current_file[36:-8]], f)
				# json.dump([[], [], malicious_labels, malicious_labels_events, user_artifact, classified_words, 	prediction[:, 0].tolist()[:len(z_test)], prediction_proba.tolist()[:len(z_test)], ofile_lines, 	current_file], f)
				exit()
		
		prediction_counter += 1
		WORK_UPDATED = False
		if len(work_list) == 0:
			break
		
		for work in work_list:
			done_work_counter += 1
			x_test = []
			y_test = []
			z_test = []

			for l in possible_labels:
				if l in work:
					continue
				work_seq = construct_seq_using_labels(lines, work)
				work_branch = work[:]
				work_branch.append(l)
				work_branch_seq = construct_seq_using_labels(lines, work_branch)
				if len(work_branch_seq.split()) > maxlen or len(work_seq.split()) == len(work_branch_seq.split()):
					continue
				tokenized_work_branch_seq = tokenize_sequences(work_branch_seq)
				words = []
				for w in tokenized_work_branch_seq.split():
					words.append(tokenized_elements[w])
				
				x_test.append(words)
				
				# This block is for evaluation purposes
				MATCHED = False
				if tokenized_work_branch_seq in mal_com_seq_list:
					MATCHED = True
					y_test.append(1)
				if not MATCHED:
					y_test.append(0)

				z_test.append(work_branch)
			
			work_seq = construct_seq_using_labels(lines, work)
			if len(work_seq.split()) > maxlen:
				continue
			tokenized_work_seq = tokenize_sequences(work_seq)
			words = []
			for w in tokenized_work_seq.split():
				words.append(tokenized_elements[w])
			
			x_test.append(words)
			z_test.append(work)

			if len(x_test) > 0:
				x_test = sequence.pad_sequences(x_test, maxlen=maxlen, padding="post")

				predicted_labels, labels_candidates = predict_labels()
				lll_c = 0
				i_to_del = []
				for lll in labels_candidates:
					if "c:/users/aalsahee/downloads" in lll[0]:
						i_to_del.append(lll_c)
					lll_c += 1
				
				for iii in reversed(i_to_del):
					del labels_candidates[iii]
				
				lll_c = 0
				i_to_del = []
				for lll in labels_candidates:
					llll_c = 0
					for llll in lll[0]:
						if "192.168.223.128" in llll or "192.168.223.130" in llll:
							i_to_del.append(lll_c)
							break
						llll_c += 1
					lll_c += 1

				for iii in reversed(i_to_del):
					del labels_candidates[iii]
					
				labels_candidates = sorted(labels_candidates, key = lambda x: (x[1]), reverse=True)
				
				for lc in labels_candidates:
					if not lc[0] in work_list:
						WORK_UPDATED = True
						CONVERGED = True
						work_list.append(lc[0])
						lc0_len = len(lc[0])
						if lc0_len in list(result_labels):
							if lc[1] >= 0.50:
								result_labels[lc0_len].append(lc)
						else:
							if lc[1] >= 0.50:
								result_labels[lc0_len] = [lc]
			break
		
		del work_list[0]
	print("len(labels_candidates) = " + str(len(labels_candidates)))
	print(labels_candidates)
	#print "len(predicted_labels) = " + str(len(predicted_labels))
	print(result_labels[list(result_labels)[-1]])

	return result_list

def get_active_actions_statements(lines):
	subjects = []
	subjects_statements = []

	for statement in lines:
		if statement.split()[1] == "write" or statement.split()[1] == "connect":
			if not statement.split()[2] in subjects:
				subjects.append(statement.split()[2])
			
	for statement in lines:
		if not statement.split()[0] in subjects:
			subjects.append(statement.split()[0])

	for statement in lines:
		if statement.split()[0] in subjects and statement.split()[2] in subjects:
			if not statement in subjects_statements:
				subjects_statements.append(statement)

	return subjects_statements, subjects


def abstract_to_logs_sequences(lines):
	global classified_words, classified_words_prediction, classified_words_proba, prob_updated

	print("\nTotal statements (including passive-actions statements): " + str(len(lines)))
	subjects_statements, subjects = get_active_actions_statements(lines)
	print("Active-actions statements: " + str(len(subjects_statements)))
	print("Possible labels: " + str(len(subjects)) + "\n")

	classified_words = subjects[:]
	classified_words_prediction = np.zeros(len(classified_words))
	classified_words_proba = np.zeros(len(classified_words))
	prob_updated = np.zeros(len(classified_words))
	
	if not TESTING_STARTED:
		result_list = suggest_ground_truth(subjects_statements, subjects)
	else:
		result_list = testing_suggest_ground_truth(subjects_statements, subjects)

	return result_list, subjects_statements

def train():
	global cvscores, kfold, CUSTOM_FIT, model, max_features, maxlen, x_train, y_train, batch_size, SHOW_STAT

	
	history = None
	early_stopping = EarlyStopping(monitor='val_loss', patience=32)
	class_weight = {0: 1., 1: 50.}
	callbacks_list = [keras.callbacks.EarlyStopping(monitor='acc', patience=1), keras.callbacks.ModelCheckpoint(filepath='my_model.h5', monitor='val_loss', save_best_only=True)]

	if CUSTOM_FIT == 0:
		if SHOW_STAT:
			history = model.fit(x_train, y_train,
        	  batch_size=batch_size,
        	  epochs=EPOCH, validation_split=0.20) #, callbacks=callbacks_list
		else:
			history = model.fit(x_train, y_train,
        	  batch_size=batch_size,
        	  epochs=EPOCH)
	elif CUSTOM_FIT == 2: # Cross-validation k-fold
		SHOW_STAT = False
		for train, test in kfold.split(x_train, y_train):
			# reset the model
			generate_model()
			# Fit the model
			model.fit(x_train[train], y_train[train], epochs=EPOCH, batch_size=batch_size, verbose=0)
			# evaluate the model
			scores = model.evaluate(x_train[test], y_train[test], verbose=0)
			print("%s: %.2f%%" % (model.metrics_names[1], scores[1]*100))
			cvscores.append(scores[1] * 100)
		print("%.2f%% (+/- %.2f%%)" % (np.mean(cvscores), np.std(cvscores)))

	if SHOW_STAT:
		# summarize history for accuracy
		plt.plot(history.history['acc'])
		plt.plot(history.history['val_acc'])
		plt.title('model accuracy')
		plt.ylabel('accuracy')
		plt.xlabel('epoch')
		plt.legend(['train', 'test'], loc='upper left')
		plt.savefig("test_acc.png")
		plt.show()
		
		# summarize history for loss
		plt.plot(history.history['loss'])
		plt.plot(history.history['val_loss'])
		plt.title('model loss')
		plt.ylabel('loss')
		plt.xlabel('epoch')
		plt.legend(['train', 'test'], loc='upper left')
		plt.savefig("test_loss.png")
		plt.show()

classified_words = []
classified_words_prediction = []
classified_words_proba = []
prob_updated = []
def predict_labels():
	global prediction_counter, current_file, malicious_labels, maximum_number_of_test_iterations, user_artifact
	global classified_words, classified_words_prediction, classified_words_proba, prob_updated
	global CUSTOM_FIT, prediction, x_test, y_test, z_test

	filter_result = []
	false_positives = 0
	false_negatives = 0
	correctly_identified = 0
	total_sequences = 0
	predicted_malicious_labels = []
	labels_candidates = []
	prediction = None
	prediction_proba = None
	argmax = None

	if CUSTOM_FIT == 0:
		prediction = model.predict_classes(x_test)
		prediction_proba = model.predict_proba(x_test)[:, 0]

		prediction = prediction[:, 0].tolist()
		prediction_proba = prediction_proba.tolist()
		
		cc = 0
		for sublist in z_test:
			current_word = sublist[-1]

			if not current_word in classified_words:
				if not current_word == user_artifact:
					print("ERROR!!")
					print(current_word)
			else:
				current_word_index = classified_words.index(current_word)
				if prediction[cc] == 1:
					classified_words_prediction[current_word_index] = prediction[cc]
					if prediction_proba[cc] > classified_words_proba[current_word_index]:
						classified_words_proba[current_word_index] = prediction_proba[cc]
				elif prediction[cc] == 0 and classified_words_prediction[current_word_index] == 0:
					if prob_updated[cc] == 0:
						prob_updated[cc] = 1
						classified_words_proba[current_word_index] = prediction_proba[cc]
					else:
						if prediction_proba[cc] < classified_words_proba[current_word_index]:
							classified_words_proba[current_word_index] = prediction_proba[cc]
			cc += 1

	for x in range(0, len(prediction)):
		if prediction[x] == 1:
			if CUSTOM_FIT == 0:
				labels_candidates.append((z_test[x], prediction_proba[x]))
		if prediction[x] == 0 and prediction_proba[x] > 0.5:
			print(z_test[x])

	
	return predicted_malicious_labels, labels_candidates



def prepare_dataset(lines, preprocessed_logs_file):
	global current_file
	global x_dataset, y_dataset, z_dataset, max_features, maxlen, malicious_labels
	
	current_file = preprocessed_logs_file
	result_list = []

	print(preprocessed_logs_file + " processing...")
	
	result_list, subjects_statements = abstract_to_logs_sequences(lines)

	for s in result_list:
		words = []
		
		for w in s[1].split():
			words.append(tokenized_elements[w])
		
		if not words in x_dataset:
			x_dataset.append(words)
		else:
			continue
		z_dataset.append(s[0])
		y_dataset.append(s[2])

	print("done.\n")
	return x_dataset, y_dataset, z_dataset, subjects_statements


def generate_malicious_sequences(lines):
	global user_artifact, malicious_labels, mal_com_seq_list

	longest_mal_seq = 0

	for r in range(1, len(malicious_labels)+1):
		for mal_combo in combinations(malicious_labels, r):
			mal_combo_list = [user_artifact]
			
			for i in mal_combo:
				mal_combo_list.append(i)

			mal_com_seq = construct_seq_using_labels(lines, mal_combo_list)
			tokenized_mal_com_seq = tokenize_sequences(mal_com_seq)
			if len(tokenized_mal_com_seq.split()) > longest_mal_seq:
				longest_mal_seq = len(tokenized_mal_com_seq.split())
				# print("INFO: Longer malicious training sequence has been found: " + str(longest_mal_seq))
			
			if len(tokenized_mal_com_seq.split()) > maxlen:
				print("WARNING: malicious training sequence is longer than maxlen: " + str(len(tokenized_mal_com_seq.split())))

			if not tokenized_mal_com_seq in mal_com_seq_list:
				mal_com_seq_list.append(tokenized_mal_com_seq)

if __name__ == '__main__':
	
	lines = []

	if DO_TRAINING:
		print('Train...')
		#'''
		if load_nonsampling:
				print("Loading nonsampled datasets ...")
				nonsampling_in = open("resampling/nonsampling.json")
				x_y_z_list = json.load(nonsampling_in)
				x_train = x_y_z_list[0]
				y_train = x_y_z_list[1]
				z_train = x_y_z_list[2]
		elif load_resampling:
			print("Loading resampled datasets ...")
			resampling_in = open("resampling/resampling.json")
			x_y_z_list = json.load(resampling_in)
			x_train = x_y_z_list[0]
			y_train = x_y_z_list[1]
			z_train = x_y_z_list[2]
		elif load_undersampling:
			print("Loading undersampled datasets ...")
			undersampling_in = open("resampling/undersampling.json")
			x_y_z_list = json.load(undersampling_in)
			x_train = x_y_z_list[0]
			y_train = x_y_z_list[1]
			z_train = x_y_z_list[2]
		else:
			# nonsampling start time
			start = time.time()
			# gather all malicious sequences
			for file in os.listdir("output"):
				if file.startswith("seq_graph_training_"):
					print("1- file: " + file)
					
					load_malicious_labels(file)
					malicious_labels_len = len(malicious_labels)
					input_file_path = "output/" + file
					input_file = open(input_file_path, "r")
					lines = input_file.readlines()
	
					for i in range(0, malicious_labels_len):
						load_malicious_labels(file)
						user_artifact = malicious_labels[i]
						malicious_labels.remove(user_artifact)
						subjects_statements, subjects = get_active_actions_statements(lines)
						generate_malicious_sequences(subjects_statements)
						print("user_artifact: " + user_artifact)
			
			print("##########################################")
			for file in os.listdir("output"):
				if file.startswith("seq_graph_training_"):
					print("2- file: " + file)
					
					load_malicious_labels(file)
					malicious_labels_len = len(malicious_labels)
					input_file_path = "output/" + file
					input_file = open(input_file_path, "r")
					lines = input_file.readlines()
					
					
					for i in range(0, malicious_labels_len):
						load_malicious_labels(file)
						user_artifact = malicious_labels[i]
						malicious_labels.remove(user_artifact)
						x_train, y_train, z_train, subjects_statements = prepare_dataset(lines, file)
						print("user_artifact: " + user_artifact)
						print("Total learning samples: " + str(len(x_train)))
			
			combined = list(zip(x_train, y_train))
			combined = sorted(combined, key = lambda x: x[1], reverse=True)
	
			x_train[:], y_train[:] = zip(*combined)
	
			tokenized_x_train = []
	
			for x in x_train:
				temp_x = ""
				for xx in x:
					temp_x += tokenized_x_train_elements[xx] + " "
				temp_x = "".join(temp_x.split(" "))
				tokenized_x_train.append(temp_x.rstrip())
	
			print("y_train[:30]: " + str(list(y_train)[:30]))
	
			count_y_0 = 0
			count_y_1 = 0
	
			for yval in list(y_train):
				#print yval
				if yval == 1:
					count_y_1 += 1
				if yval == 0:
					count_y_0 += 1
	
			print("zeros: " + str(count_y_0))
			print("ones: " + str(count_y_1))

			if not load_nonsampling:
				done = time.time()
				elapsed = done - start
				print("Nonsampling time: " + str(elapsed))

				x_y_z_list = [x_train, y_train, z_train]

				if os.path.exists("resampling/nonsampling.json"):
					os.remove("resampling/nonsampling.json")
					
				nonsampling_out = open("resampling/nonsampling.json", 'w')
				json.dump(x_y_z_list, nonsampling_out)
				nonsampling_out.close()
				print("Saved nonsampling.json file ...")

				# reset for undersampling time
				start = time.time()

			print("Generating undersampled datasets ...")
			if count_y_1 < count_y_0:
				j_to_be_del = []

				for x_t_i in range(count_y_1, len(y_train)):
					if x_t_i in j_to_be_del:
						continue

					for x_t_j in range(x_t_i+1, len(y_train)):
						if x_t_j in j_to_be_del:
							continue
						pr = fuzz.ratio(tokenized_x_train[x_t_i], tokenized_x_train[x_t_j])
						if pr >= u_thresh:
							j_to_be_del.append(x_t_j) 

				j_to_be_del.sort(reverse=True)
				for j_del in j_to_be_del:
					del x_train[j_del]
					del y_train[j_del]
					del z_train[j_del]
					del tokenized_x_train[j_del]

				count_y_0 = 0
				count_y_1 = 0
		
				for yval in list(y_train):
					if yval == 1:
						count_y_1 += 1
					if yval == 0:
						count_y_0 += 1
		
				print("after undersampling the dataset: ")
				print("zeros: " + str(count_y_0))
				print("ones: " + str(count_y_1))

				if not load_undersampling:
					done = time.time()
					elapsed = done - start
					print("Undersampling time: " + str(elapsed))
					x_y_z_list = [x_train, y_train, z_train]

					if os.path.exists("resampling/undersampling.json"):
						os.remove("resampling/undersampling.json")

					undersampling_out = open("resampling/undersampling.json", 'w')
					json.dump(x_y_z_list, undersampling_out)
					undersampling_out.close()
					print("Saved undersampling.json file ...")
					
					# reset for oversampling time
					start = time.time()
				
				# over-sampling
				if count_y_1 < count_y_0:
					number_of_iterations = count_y_0 - count_y_1
					x_train_t, y_train_t, z_train_t = x_train[:count_y_1], y_train[:count_y_1], z_train[:count_y_1]
					for i_n in range(0, number_of_iterations):
						i_n_mod = i_n % count_y_1
						x_train = [x_train_t[i_n_mod]] + x_train
						y_train = [y_train_t[i_n_mod]] + y_train
						z_train = [z_train_t[i_n_mod]] + z_train
		
					count_y_0 = 0
					count_y_1 = 0
			
					for yval in list(y_train):
						#print yval
						if yval == 1:
							count_y_1 += 1
						if yval == 0:
							count_y_0 += 1
					
					print("after oversampling the dataset: ")
					print("zeros: " + str(count_y_0))
					print("ones: " + str(count_y_1))
					
					done = time.time()
					elapsed = done - start
					print("Overampling time: " + str(elapsed))
					x_y_z_list = [x_train, y_train, z_train]

					if os.path.exists("resampling/resampling.json"):
						os.remove("resampling/resampling.json")
						
					resampling_out = open("resampling/resampling.json", 'w')
					json.dump(x_y_z_list, resampling_out)
					resampling_out.close()
					print("Saved resampling.json file ...")
					
					exit()

		combined = list(zip(x_train, y_train))
		random.Random(seed).shuffle(combined)
		random.shuffle(combined)
		x_train[:], y_train[:] = zip(*combined)

		x_train = sequence.pad_sequences(x_train, maxlen=maxlen, padding="post")
		y_train = np.array(y_train)

		start = time.time()
		train()
		done = time.time()
		elapsed = done - start
		print("Training time: " + str(elapsed))
		# save model and weights
		print('Save the model...')
		model.save('output/model.h5')
		exit()

	TESTING_STARTED = True

	# testing
	for file in os.listdir("output"):
		if file.startswith("seq_graph_testing_"):
			load_malicious_labels(file)
			user_artifact = malicious_labels[0]
			print("\nLoading the malicious labels:")
			print(str(malicious_labels) + "\n")
			input_file_path = "output/" + file
			input_file = open(input_file_path, "r")
			lines = input_file.readlines()
			x_test, y_test, z_test, subjects_statements = prepare_dataset(lines, file)