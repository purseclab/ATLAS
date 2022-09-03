# ATLAS

This repository contains artifacts for the paper:
"ATLAS: A Sequence-based Learning Approach for Attack Investigation" accepted at the 30th USENIX Security Symposium.

<p>
<a href="https://cssaheel.github.io/sec21summer_alsaheel.pdf
"> <img align="right" width="220"  src="https://cssaheel.github.io/atlas-cover-page.png"> </a> 
</p>

<br>

## Note

The artifacts in this repository include ATLAS source code, and audit logs that include the APT attacks we detailed in the paper.
If you have used any of the artifacts published in this repository, please acknowledge the use by citing our paper.<br>
```
@inproceedings{alsaheel2021atlas,
  title={$\{$ATLAS$\}$: A sequence-based learning approach for attack investigation},
  author={Alsaheel, Abdulellah and Nan, Yuhong and Ma, Shiqing and Yu, Le and Walkup, Gregory and Celik, Z Berkay and Zhang, Xiangyu and Xu, Dongyan},
  booktitle={30th USENIX Security Symposium (USENIX Security 21)},
  pages={3005--3022},
  year={2021}
}
```

## Dependencies
- Python 3 (tested on Python 3.7.7)
- TensorFlow 2.3.0
- keras 2.4.3
- fuzzywuzzy 0.18.0
- matplotlib 2.2.5
- numpy 1.16.6
- networkx 2.2

## How to use
The "paper_experiments" folder includes individual folders for all the experiments presented in the paper.
Each folder contains a copy of ATLAS so that the experiments results can be easily reproduced.
Each experiment folder contains the preprocessed log files, thus, you could skip the steps (A) through (C) listed below. However, the raw audit logs can be found in the folder "raw_logs". 

(A) preprocess.py usage:
- execute the command "python3 preprocess.py"
to preprocess the "logs" folders located in the training_logs and testing_logs folders, and
for each "logs" folder it will generate one preprocessed logging file at the "output" folder.

(B) graph_generator.py usage:
- execute the command "python3 graph_generator.py"
to take each preprocessed logs files from the "output" folder and generate a corresponding graph file at the "output" folder.

(C) graph_reader.py usage:
- execute the command "python3 graph_reader.py"
to take each graph file from the "output" folder and generate a corresponding sequence (text) file at the "output" folder.

(D) atlas.py usage:
- edit atlas.py and set the variable "DO_TRAINING" to "True", or set it to "False" if you would like to do testing instead.
- execute the command "python3 atlas.py" to run ATLAS.

ATLAS "training" phase output:
- model.h5 will be written to the "output" folder, now you can proceed to ATLAS "testing" phase.

ATLAS "testing" phase output:
- ATLAS will predict the attack entities and will print each attack entity with its prediction probability score similar to this:
[(["0xalsaheel.com", "c:/users/aalsahee/index.html"], 0.9724874496459961), (["0xalsaheel.com", "192.168.223.3"], 0.9721188545227051), (["0xalsaheel.com", "c:/users/aalsahee/payload.exe"], 0.9706782698631287), (["0xalsaheel.com", "c:/users/aalsahee/payload.exe_892"], 0.8397794365882874), (["0xalsaheel.com", "c:/users/aalsahee/payload.exe_1520"], 0.6693234443664551)]

Do some manual cleaning, such that you remove the redundant attack entities such as the file "payload.exe" and its redundant
attack process entity "payload.exe_892" (both entities refer to the same file).
Moreover, you could also add "obviously" related attack entities if needed, for example
if ATLAS reported that "0xalsaheel.com" is an attack entity then obviously
its resolved IP address "192.168.223.3" is also an attack entity.
After doing this, the result shown above should become similar to this:
["0xalsaheel.com", "aalsahee/index.html", "192.168.223.3", "payload.exe"]

(E) evaluate.py usage:
- After you finish ATLAS testing phase, a JSON file that starts with the name "eval_**" is generated in the "output" folder.
You will have to edit that file by opening it in a text editor, then replace the first "[]" with your
cleaned result (e.g., ["0xalsaheel.com", "aalsahee/index.html", "192.168.223.3", "payload.exe"]), then save the file.

NOTE: If this result is for a host (e.g., h1) in a multi-host attack scenario (e.g., M1), then copy the JSON
file to the "output" folder in the second host folder (e.g., h2), this way when we run the
evaluate.py program (in h2 folder) it will consider all involved hosts.

- execute the command "python3 evaluate.py"
and the final result will be printed based on all the json eval_** files stored at the "output" folder.

NOTE: To find the precision, recall and f1-score for each experiment, we use the number of false positives and negatives reported by atlas and we update them at the Excel sheet paper_experiments/docs/atlas.xlsx to get the result.
