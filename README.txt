The Codes directory contains the datasets and source codes for data processing and training different IDS.

Dataset Directories:
a. Adversary/ : This folder contains the json files for the DNP3 and ARP based packets captured at the attacker machine used
 for constructing the labels. For example : UC1_PyDNP3_CORE_Adversary_10_OS_30_dnp3.json file is for the usecase 1 described 
 in the RESLab paper with 10 DNP3 outstations monitored at 30 sec polling interval.

b. csvs/ : This folder contains all the processed and encoded files obtained after the merge and extraction process from 
multiple sources. The sub-directories distributes the files based on the use case. For example: DS_merged_phy_cyb_10os_30poll.csv
file within the usecase 1 contains the merged and processed file for the usecase 1 described in the RESLab paper with 10 DNP3 
outstations monitored at 30 sec polling interval.

c. RawFiles/ : This folder contains raw files obtained from different sources. This folder contains sub-directories : DS, master,
router and snort. The snort sub-directory contains snort logs running in the substation router for different use-cases.
For example: UC1_PyDNP3_CORE_Snort_10_OS_30_1017 file is for the usecase 1 described in the RESLab paper with 10 DNP3 outstations 
monitored at 30 sec polling interval. The master, DS, router folder contains csvs/, PickleFiles/, and Raw/ sub-directories. 
The csvs/ folders contains the same files present in the csvs folder mentioned in the previous directory.
The PickleFiles/ folders contains the pickle files obtained from Pyshark libraries for adding additional features such as 
Round Trip Time (RTT) and restransmissions.
The Raw/ folders contains the raw pcap files in JSON format for creating the cyber and raw physical features.

  
Python Codes:
a. DataFusion : This is the primary class used for collecting data from multi-sensors and merging them to form the
primary cyber and physical dataframe. This class basically performs the Algorithm 1 discussed in the paper.

b. FetchEachStepData : It is used to extract datasets in each steps followed in the Algorithm 1. The details
on the arguments to be passed can be found in the code.

c. SupervisedLearning : The dataset generated from the DataFusion class is used for training different classifiers discussed in
Section Viii RESULTS AND ANALYSIS (A) SUPERVISED TECHNIQUE INTRUSION DETECTION

d. SupervisedLearning_HyperParameter_Tuning.ipynb : This is the jupyter notebook for hyper-parameter tuning using GridSearch.

e. Unsupervised_Learning_Clustering.ipynb : This is the jupyter notebook for clustering techniques evaluation. 

f. Manifold_Learning_Experiments.ipynb : This is the jupyter notebook for feature reduction using manifold learning followed by supervised learning. 

g. CoTraining : This is one of the semi-supervised learning based IDS implementation using CoTraining. The details
on the arguments to be passed can be found in the code.



 
