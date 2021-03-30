__author__ = "Abhijeet Sahu"
__credits__ = ["Abhijeet Sahu"]
__email__ = "abhijeet_ntpc@tamu.edu"
__affiliation__ = "Texas A&M University"


import pandas as pd
import xlsxwriter
import numpy as np
from DataFusion import DataFusion
import time
import datetime
from sklearn.model_selection import train_test_split
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import confusion_matrix
from sklearn.metrics import average_precision_score
from sklearn.metrics import confusion_matrix 
from sklearn.metrics import accuracy_score 
from sklearn.metrics import classification_report 
from sklearn import svm
from sklearn import tree
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.naive_bayes import BernoulliNB
from sklearn.neural_network import MLPClassifier

from sklearn.metrics import precision_recall_curve
from sklearn.metrics import plot_precision_recall_curve
import msgpack as mp
import sys
from sklearn.metrics import precision_recall_fscore_support

def get_intrusion_window(adversary_path):
    fusion = DataFusion()
    fusion.load_json(adversary_path)
    fusion.extract_cyber_data()
    fusion.extract_physical_data()
    data_to_process = fusion.merge()
    attack_start = data_to_process.iloc[0]['Time']
    start = int(time.mktime(attack_start.timetuple()))
    attack_end = data_to_process.iloc[-1]['Time']
    end = int(time.mktime(attack_end.timetuple()))
    return start,end

def supervised_learning(_usecase,_os,_poll_rate, location, pca, pure_cyber=False, pure_phy=False):
    usecase=_usecase
    os=_os
    poll_rate = _poll_rate
    common_path = '../data/'
    if os==10 and poll_rate ==60 and usecase=='UC1':
        path='csvs/UC1/'+location+'_merged_phy_cyb_10os_60poll_encoded.csv'
        adv_path='Adversary/UC1_PyDNP3_CORE_Adversary_10_OS_60_dnp3.json'
    elif os==10 and poll_rate ==30 and usecase=='UC1':
        path='csvs/UC1/'+location+'_merged_phy_cyb_10os_30poll_encoded.csv'
        adv_path='Adversary/UC1_PyDNP3_CORE_Adversary_10_OS_30_dnp3.json'
    elif os==5 and poll_rate ==30 and usecase=='UC2':
        path='csvs/UC2/uc2_'+location+'_merged_phy_cyb_5os_30poll_encoded.csv'
        adv_path='Adversary/UC2_PyDNP3_CORE_Adversary_5_OS_30_dnp3.json'
    elif os==5 and poll_rate ==60 and usecase=='UC2':
        path='csvs/UC2/uc2_'+location+'_merged_phy_cyb_5os_60poll_encoded.csv'
        adv_path='Adversary/UC2_PyDNP3_CORE_Adversary_5_OS_60_dnp3.json'
    elif os==10 and poll_rate ==30 and usecase=='UC2':
        path='csvs/UC2/uc2_'+location+'_merged_phy_cyb_10os_30poll_encoded.csv'
        adv_path='Adversary/UC2_PyDNP3_CORE_Adversary_10_OS_30_dnp3.json'
    elif os==10 and poll_rate ==60 and usecase=='UC2':
        path='csvs/UC2/uc2_'+location+'_merged_phy_cyb_10os_60poll_encoded.csv'
        adv_path='Adversary/UC2_PyDNP3_CORE_Adversary_10_OS_60_dnp3.json'
    elif os==5 and poll_rate ==30 and usecase=='UC3':
        path='csvs/UC3/uc3_'+location+'_merged_phy_cyb_5os_30poll_encoded.csv'
        adv_path='Adversary/UC3_PyDNP3_CORE_Adversary_5_OS_30_dnp3.json'
    elif os==5 and poll_rate ==60 and usecase=='UC3':
        path='csvs/UC3/uc3_'+location+'_merged_phy_cyb_5os_60poll_encoded.csv'
        adv_path='Adversary/UC3_PyDNP3_CORE_Adversary_5_OS_60_dnp3.json'
    elif os==10 and poll_rate ==30 and usecase=='UC3':
        path='csvs/UC3/uc3_'+location+'_merged_phy_cyb_10os_30poll_encoded.csv'
        adv_path='Adversary/UC3_PyDNP3_CORE_Adversary_10_OS_30_dnp3.json'
    elif os==10 and poll_rate ==60 and usecase=='UC3':
        path='csvs/UC3/uc3_'+location+'_merged_phy_cyb_10os_60poll_encoded.csv'
        adv_path='Adversary/UC3_PyDNP3_CORE_Adversary_10_OS_60_dnp3.json'
    elif os==5 and poll_rate ==30 and usecase=='UC4':
        path='csvs/UC4/uc4_'+location+'_merged_phy_cyb_5os_30poll_encoded.csv'
        adv_path='Adversary/UC4_PyDNP3_CORE_Adversary_5_OS_30_dnp3.json'
    elif os==5 and poll_rate ==60 and usecase=='UC4':
        path='csvs/UC4/uc4_'+location+'_merged_phy_cyb_5os_60poll_encoded.csv'
        adv_path='Adversary/UC4_PyDNP3_CORE_Adversary_5_OS_60_dnp3.json'
    elif os==10 and poll_rate ==30 and usecase=='UC4':
        path='csvs/UC4/uc4_'+location+'_merged_phy_cyb_10os_30poll_encoded.csv'
        adv_path='Adversary/UC4_PyDNP3_CORE_Adversary_10_OS_30_dnp3.json'
    elif os==10 and poll_rate ==60 and usecase=='UC4':
        path='csvs/UC4/uc4_'+location+'_merged_phy_cyb_10os_60poll_encoded.csv'
        adv_path='Adversary/UC4_PyDNP3_CORE_Adversary_10_OS_60_dnp3.json'


    start_time,end_time = get_intrusion_window(common_path+adv_path)
    data = pd.read_csv(common_path+path)


    #data.drop('Unnamed:0',1)
    data = data.drop(data.columns[[0]], axis=1)
    data['DNP3 Objects'].replace('None', np.nan, inplace=True)

    replace_map = dict([('DNP3 Objects',0),('value1', 0.0), ('value2', 0.0), ('value3', 0.0), 
                   ('value4', 0.0),('value5',0.0)])

    # fill nan by replace values
    data = data.fillna(value=replace_map)

    data['Time'] = pd.to_datetime(data['Time'])

    data['Label'] = 0
    for i,val in data.iterrows():
        unix_time = int(time.mktime(val['Time'].timetuple()))
        if unix_time <end_time and unix_time>start_time:
            data['Label'][i] = 1

    # compute the feature table
    feature_table = data.drop(columns=['Time', 'snort_alert', 'snort_alert_type','Label'])
    if pure_cyber:
        feature_table = data.drop(columns=['Time', 'snort_alert', 'snort_alert_type','Label','LL_dnp3_src','LL_dnp3_dst'
                                           ,'LL_dnp3_len','LL_dnp3_ctl','TL_dnp3_tr_ctl','AL_dnp3_al_func','AL_dnp3_al_ctl'
                                           ,'DNP3 Object Count','DNP3 Objects','AL_Payload'])
        
        # drop physical value features
        feature_table = feature_table[feature_table.columns[~feature_table.columns.str.contains('value')]]
        print(feature_table.columns)
    if pure_phy:
        feature_table = data.drop(columns=['Time', 'snort_alert', 'snort_alert_type','frame_len','frame_protocols','eth_src','eth_dst'
                                           ,'ip_src','ip_dst','ip_len','ip_flags','tcp_srcport','tcp_dstport','tcp_len'
                                           ,'tcp_flags','tcp_retransmission','tcp_rtt','flow_count','flow_final_count','packets','Label'])

    feature_array = feature_table.to_numpy()
    label_array = data[['Label']].to_numpy().flatten()
    
    
    # using panda dataframe to store the probability scores to be used later on in the DS theory paper
    prob_table = pd.DataFrame()
    score_table = pd.DataFrame()
    
    X_train, X_test, y_train, y_test = train_test_split(feature_array, label_array, test_size=0.33, random_state=42)
    # if pca
    if (pca):
        # Now use PCA for dimensional reduction and reperform the supervised learning
        from sklearn.decomposition import PCA
        pca = PCA(n_components=10)
        pca.fit(feature_table.values)

        pca_result = pca.transform(feature_table.values)
        pca_table1 = pd.DataFrame(columns=['f1', 'f2', 'f3', 'f4', 'f5','f6', 'f7', 'f8', 'f9', 'f10'])
        for i in range(10):
            pca_table1[f'f{i+1}'] = pca_result[:,i]

        pca_feature_array = pca_table1.to_numpy()
    
        X_train, X_test, y_train, y_test = train_test_split(pca_feature_array, label_array, test_size=0.33, random_state=42)

    clf = KNeighborsClassifier()
    clf.fit(X_train, y_train)
    predictions = clf.predict(X_test)
    
    res_knn = precision_recall_fscore_support(y_test, predictions, average='weighted')   
    probs = clf.predict_proba(X_test)
    probs = probs[:, 1]
    score_table['knn'] = probs
    prob_table['knn'] = res_knn
 
    clf = svm.SVC(probability=True)
    clf.fit(X_train, y_train)
    predictions = clf.predict(X_test)
    res_svc = precision_recall_fscore_support(y_test, predictions, average='weighted')
    probs = clf.predict_proba(X_test)
    probs = probs[:, 1]
    score_table['svc'] = probs
    prob_table['svc'] = res_svc
    
    
    dt = tree.DecisionTreeClassifier()
    dt.fit(X_train, y_train)
    dtpredictions = dt.predict(X_test)
    res_dt = precision_recall_fscore_support(y_test, dtpredictions, average='weighted')
    probs = dt.predict_proba(X_test)
    probs = probs[:, 1]
    score_table['dt'] = probs
    prob_table['dt'] = res_dt
    
    
    rf = RandomForestClassifier(n_estimators=10)
    rf.fit(X_train, y_train)
    rfpredictions = rf.predict(X_test)
    res_rf = precision_recall_fscore_support(y_test, rfpredictions, average='weighted')
    probs = rf.predict_proba(X_test)
    probs = probs[:, 1]
    score_table['rf'] = probs
    prob_table['rf'] = res_rf
    
    gnb = GaussianNB()
    gnb.fit(X_train, y_train)
    gnbpredictions = gnb.predict(X_test)
    res_gnb = precision_recall_fscore_support(y_test, gnbpredictions, average='weighted')
    probs = gnb.predict_proba(X_test)
    probs = probs[:, 1]
    score_table['gnb'] = probs
    prob_table['gnb'] = res_gnb
    
    bnb = BernoulliNB()
    bnb.fit(X_train, y_train)
    bnbpredictions = bnb.predict(X_test)
    res_bnb = precision_recall_fscore_support(y_test, bnbpredictions, average='weighted')
    probs = bnb.predict_proba(X_test)
    probs = probs[:, 1]
    score_table['bnb'] = probs
    prob_table['bnb'] = res_bnb
    
    
    nn = MLPClassifier(solver='lbfgs', alpha=1e-5,hidden_layer_sizes=(5, 2), random_state=1)
    nn.fit(X_train, y_train)
    nnpredictions = nn.predict(X_test)
    res_nn = precision_recall_fscore_support(y_test, nnpredictions, average='weighted')
    probs = nn.predict_proba(X_test)
    probs = probs[:, 1]
    score_table['nn'] = probs
    prob_table['mlp'] = res_nn
    #prob_table = prob_table.drop(columns=['Time'])
    print(prob_table)
    print(score_table)
    return prob_table,score_table
    
#### Arguments ##############
'''
argument 1: use case Example: UC1_5OS_60poll , i.e. use case 1, with 5 DNP3 outstation polled with a polling interval of 60 sec
argument 2: boolean to enable feature reduction using PCA
argument 3: pc: If pure Cyber features considered
argument 4: pp: If pure physical features considered
argument 5: Select the location for collecting the raw data. Select either : "master", "DS", "router" 
'''
case = sys.argv[1]
enable_PCA = sys.argv[2]
pc = sys.argv[3]
pp = sys.argv[4]
location = sys.argv[5]
_usecase = case.split('_')[0]
print(_usecase)
outstations = case.split('_')[1]
_os = outstations.replace('OS','')
poll_interval = case.split('_')[2]
_pi = poll_interval.replace('poll','')
data_as_df,score_as_df = supervised_learning(_usecase,int(_os),int(_pi),location, pca=enable_PCA,pure_cyber= pc, pure_phy=pp)
data_as_list = data_as_df.values.tolist()
score_as_list = score_as_df.values.tolist()
mp.pack(data_as_list, open('pscores_'+sys.argv[1]+'.mp','wb'))
mp.pack(score_as_list, open('prob_'+sys.argv[1]+'.mp','wb'))
