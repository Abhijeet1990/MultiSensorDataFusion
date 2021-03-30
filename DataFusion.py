
__author__ = "Zeyu Mao, Abhijeet Sahu"
__credits__ = ["Zeyu Mao", "Abhijeet Sahu"]
__email__ = "zeyumao2@tamu.edu, abhijeet_ntpc@tamu.edu"
__affiliation__ = "Texas A&M University"

import json
import re
import pandas as pd
from collections import OrderedDict
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import ConnectionError
import pyshark
import numpy as np
import datetime
from idstools import unified2

JSON_BODY_EXAMPLE = {
  "query": {
    "bool": {
      "must": [
          {
              "range": {
                  "event.end": {
                      "gte": "2020-01-22T00:00:00.000Z",
                      "lte": "2020-01-26T00:00:00.000Z"
                  }
              }
          },
        {"range": {
      "event.duration": {
        "gte": 0,
        "lte": 3000000
      }
    }},
        {"bool": {"should": [
          {"match": {
          "destination.port": "20000"
        }},{
          "match": {
            "source.port": "20000"
          }
        }
        ]}}
      ,{"match": {
        "flow.final": "true"
      }}]
    }

  }
}

class DataFusion:
    def __init__(self):
        self.source = None
        self.rawdata = None
        self.physical_table = None
        self.physical_table_New= None
        self.cyber_table = None
        self.merged_table = None

        self.elasticsearch_ip = None
        self.packetbeat = None  # provide the elasticsearch index
        self.packetbeat_response = None
        self.pb_table = None  # create the data frame for the packetbeat
        self.snort_log = None  # provide the snort log file location or file name
        self.cap = None
        self.pcap_table = None
        self.snort_table = None
        self.encoder_list = None

    def _make_unique(self, key, dct):
        counter = 0
        unique_key = key

        while unique_key in dct:
            counter += 1
            unique_key = '{}_{}'.format(key, counter)
        return unique_key

    def _parse_object_pairs(self, pairs):
        dct = OrderedDict()
        for key, value in pairs:
            if key in dct:
                key = self._make_unique(key, dct)
            dct[key] = value

        return dct

    def load_json(self, file_path):
        with open(file_path) as f:
            self.rawdata = json.load(f, object_pairs_hook=self._parse_object_pairs)

    def load_pcap(self, file_path):
        self.cap = pyshark.FileCapture(file_path, display_filter="dnp3||arp")

    def extract_pcap(self):
        # assert self.cap, "PCAP is not loaded yet"
        total_records = []
        retrans = 0
        count = 0
        cap_time=[]
        for packet in self.cap:
            count+=1
            cap_time.append(packet.frame_info.time_epoch)
            try:
                try:
                    if packet.tcp.analysis_retransmission:
                        retrans = 1
                    else:
                        retrans = 0
                except AttributeError:
                    retrans = 0
                total_records.append({'Time': packet.frame_info.time_epoch, 'tcp_rtt': packet.tcp.analysis_ack_rtt,
                                      'tcp_retransmission': retrans})
            except AttributeError:
                total_records.append({'Time': packet.frame_info.time_epoch, 'tcp_retransmission': retrans})
        self.pcap_table = pd.DataFrame(total_records)
        #print(count)
        return self.pcap_table

        #return self.pcap_table
    def add_missing_rows_to_pcap(self):
        print("add missing rows")
        for index, row in self.pcap_table.iterrows():
            if row.loc['Time'] != self.cyber_table.loc[index,'Time']:
                print("add missing rows here")
                self.pcap_table = self.pcap_table.append({'Time': self.cyber_table.loc[index,'Time'], 'tcp_retransmission': 1}, ignore_index=True)
                break
        self.pcap_table = self.pcap_table.sort_values('Time')
        self.pcap_table = self.pcap_table.reset_index(drop=True)
        # for index, row in self.pcap_table.iterrows():
        #     print(row.loc['Time'], self.cyber_table.loc[index,'Time'])
        if self.pcap_table['Time'].equals(self.cyber_table['Time']):
            return self.pcap_table
        else:
            self.add_missing_rows_to_pcap()

    def merge_pcap_with_cyber(self):
        """
        Merge the PCAP table with the cyber table.
        :return: The updated cyber table (the cyber table itself will update too)
        """
        # assert self.pcap_table is None, "PCAP table is not ready! Extract the pcap first!"
        # assert self.cyber_table is None, "Cyber table is not ready!"
        if not self.pcap_table['Time'].equals(self.cyber_table['Time']):
            self.pcap_table = self.add_missing_rows_to_pcap()
        # self.cyber_table = self.cyber_table.merge(self.pcap_table, how='inner')
        self.cyber_table = self.merge_by_pcap()
        return self.cyber_table


    def extract_physical_data(self,  features=['Time', 'LL_dnp3_src', 'LL_dnp3_dst', 'LL_dnp3_len', 'LL_dnp3_ctl',
                                              'TL_dnp3_tr_ctl', 'AL_dnp3_al_func', 'AL_dnp3_al_ctl', 'AL_dnp3_obj',
                                              'DNP3 Object Count', 'DNP3 Objects', 'AL_Payload']):
        self.physical_table = pd.DataFrame(columns=features)
        total_selections = []
        for single_record in self.rawdata:
            if 'ospf' in single_record[u'_source'][u'layers'][u'frame'][u'frame.protocols']:
                continue
            record_selections = dict()
            record_selections.setdefault('Time', single_record['_source']['layers']['frame']['frame.time_epoch'])
            for key in single_record['_source']['layers']:
                # update if the source address is the outstaion number
                extraction_single_layer = self.extract_single_layer(single_record, key)
                record_selections.update(self.extract_single_layer(single_record, key))
            if 'LL_dnp3_src' in record_selections.keys():
                #if record_selections['LL_dnp3_src'] == os_number and 'DNP3 Object Count' in record_selections.keys():
                if 'DNP3 Object Count' in record_selections.keys():
                    #print(record_selections)
                    total_selections.append(record_selections)
        self.physical_table = self.physical_table.append(total_selections)
        return self.physical_table


    def extract_physical_data_new(self, os_number, features=['Time', 'LL_dnp3_src', 'LL_dnp3_dst', 'LL_dnp3_len', 'LL_dnp3_ctl',
                                              'TL_dnp3_tr_ctl', 'AL_dnp3_al_func', 'AL_dnp3_al_ctl', 'AL_dnp3_obj',
                                              'DNP3 Object Count', 'DNP3 Objects', 'AL_Payload']):
        self.physical_table = pd.DataFrame(columns=features)
        total_selections = []
        for single_record in self.rawdata:
            if 'ospf' in single_record[u'_source'][u'layers'][u'frame'][u'frame.protocols']:
                continue
            record_selections = dict()
            record_selections.setdefault('Time', single_record['_source']['layers']['frame']['frame.time_epoch'])
            for key in single_record['_source']['layers']:
                # update if the source address is the outstaion number
                extraction_single_layer = self.extract_single_layer(single_record, key)
                record_selections.update(self.extract_single_layer(single_record, key))
            if 'LL_dnp3_src' in record_selections.keys():
                if record_selections['LL_dnp3_src'] == os_number and 'DNP3 Object Count' in record_selections.keys():
                    #print(record_selections)
                    total_selections.append(record_selections)
        self.physical_table = self.physical_table.append(total_selections)
        return self.physical_table


    def extract_physical_data_with_values(self, to_monitor, features=['Time', 'LL_dnp3_src', 'LL_dnp3_dst', 'LL_dnp3_len', 'LL_dnp3_ctl','TL_dnp3_tr_ctl', 'AL_dnp3_al_func', 'AL_dnp3_al_ctl', 'AL_dnp3_obj','DNP3 Object Count', 'DNP3 Objects', 'AL_Payload']):
        for i in range(len(to_monitor)):
            features.append('value'+str(i+1))
        self.physical_table_New = pd.DataFrame(columns=features)
        total_selections = []
        for single_record in self.rawdata:
            if 'ospf' in single_record[u'_source'][u'layers'][u'frame'][u'frame.protocols']:
                continue
            record_selections = dict()
            record_selections.setdefault('Time', single_record['_source']['layers']['frame']['frame.time_epoch'])
            for key in single_record['_source']['layers']:
                # update if the source address is the outstaion number
                extraction_single_layer = self.extract_single_layer(single_record, key)
                record_selections.update(self.extract_single_layer(single_record, key))
            if 'LL_dnp3_src' in record_selections.keys():
                #if record_selections['LL_dnp3_src'] == os_number and 'DNP3 Object Count' in record_selections.keys():
                    #print(record_selections)
                if 'DNP3 Object Count' in record_selections.keys():
                    total_selections.append(record_selections)
        self.physical_table_New = self.physical_table_New.append(total_selections)
        
        ptable = self.physical_table_New
        
        # Here on we write the program to add the values from the physical Table
        data_frames={}
        for os_key in to_monitor.keys():
            ptable_os = self.extract_physical_data_new(os_key)
            if 0 not in ptable_os['DNP3 Object Count']:
                continue
            item_count = ptable_os['DNP3 Object Count'][0]
            df = pd.DataFrame(columns = np.arange(int(item_count)+1))
            for index, row in ptable_os.iterrows():
                items=[]
                # Get the current Time
                items.append(ptable_os['Time'][index])
                for key in ptable_os['AL_Payload'][index][0].keys():
                    if 'dnp3.al.obj_tree' in key:
                        for k in ptable_os['AL_Payload'][index][0][key].keys():
                            if 'Point Number' in k:
                                try:
                                    items.append(float(k.split(': ')[2]))
                                except:
                                    pass
                df_length = len(df)

                # This condition may be lost of some fields...
                if len(items) == int(item_count)+1:
                    df.loc[df_length] = items
            data_frames[os_key] = df
        
        for index,row in ptable.iterrows():
            for key in data_frames.keys():
                df_index = list(to_monitor.keys()).index(key) 
                time_list = data_frames[key][0].tolist()
                value_list = data_frames[key][to_monitor[key][0]].tolist()
                #print(key)
                #print(to_monitor[key][0])
                #print(data_frames[key][to_monitor[key][0]])
                for i in range(len(time_list)-1):
                    feature_to_update ='value'+str(df_index +1)
                    if ptable['Time'][index] >= time_list[i] and ptable['Time'][index] <=time_list[i+1]:
                        #print('Values '+str(value_list[i]))
                        ptable[feature_to_update][index] = value_list[i]
                        continue
                        
        self.physical_table_New = ptable        
        return self.physical_table_New


    def extract_single_layer(self, single_record, key):
        complete_features = dict()
        link_layer_features = dict()
        tp_layer_features = dict()
        app_layer_features = dict()
        if 'dnp3' == key:
            dnp_key = key
            # Get the link layer content
            link_layer_key = list(single_record['_source']['layers'][dnp_key].keys())[0]
            link_layer_content = single_record['_source']['layers'][dnp_key][link_layer_key]
            link_layer_subkeys = ['dnp3.src', 'dnp3.dst', 'dnp3.len', 'dnp3.ctl']
            for feature_name in link_layer_subkeys:
                link_layer_features = self.parse_key_to_features(link_layer_content, link_layer_features, feature_name,
                                                                 'Link Layer')

            if not '9' in single_record[u'_source'][u'layers'][u'dnp3'][link_layer_key][u'dnp3.ctl_tree'][
                u'dnp3.ctl.prifunc']:
                # Get the transport layer content
                tp_layer_content = single_record['_source']['layers'][dnp_key]
                tp_layer_features = self.parse_key_to_features(tp_layer_content, tp_layer_features, 'dnp3.tr.ctl',
                                                               'Transport Layer')

                # Get the application layer content
                app_layer_key = list(single_record['_source']['layers'][dnp_key].keys())[5]
                app_layer_content = single_record['_source']['layers'][dnp_key][app_layer_key]
                app_layer_subkeys = ['dnp3.al.func', 'dnp3.al.ctl', 'RESPONSE Data Objects',
                                    'READ Request Data Objects',
                                    'DIRECT OPERATE Request Data Objects']
                #app_layer_subkeys = ['dnp3.al.func', 'dnp3.al.ctl', 'RESPONSE Data Objects']
                for feature_name in app_layer_subkeys:
                    app_layer_features = self.parse_key_to_features(app_layer_content, app_layer_features, feature_name,
                                                                    'Application Layer')

        complete_features.update(link_layer_features)
        complete_features.update(tp_layer_features)
        complete_features.update(app_layer_features)
        return complete_features

    def parse_key_to_features(self, layer_records: dict, feature_collection: dict, feature_name: str, layer_name: str):
        if layer_name == 'Link Layer':
            layer_prefix = "LL"
        elif layer_name == 'Transport Layer':
            layer_prefix = "TL"
        elif layer_name == 'Application Layer':
            layer_prefix = 'AL'
        else:
            layer_prefix = 'UL'  # for unknown layer

        if feature_name in ['RESPONSE Data Objects','READ Request Data Objects','DIRECT OPERATE Request Data Objects']:
            column_name = '_'.join([layer_prefix, 'Payload'])
            if feature_collection.get(column_name, None):
                try:
                    feature_collection[column_name] = feature_collection[column_name].append(
                        layer_records[feature_name])
                except KeyError:
                    pass
            else:
                try:
                    feature_collection.setdefault(column_name, [layer_records[feature_name]])
                    feature_collection.update(self.extract_sub_dnp3_object(layer_records[feature_name], feature_name))
                except KeyError:
                    return feature_collection
        else:
            try:
                column_name = '_'.join([layer_prefix] + feature_name.split('.'))
                feature_collection.setdefault(column_name, layer_records[feature_name])
            except KeyError:
                pass
        return feature_collection

    def extract_sub_dnp3_object(self, dnp3_object: dict, feature_name: str):
        dnp3_object_common = dict()
        if feature_name == 'RESPONSE Data Objects':
            dnp3_object_common.update(self.extract_dnp3_response(dnp3_object))
        elif feature_name == 'READ Request Data Objects':
            dnp3_object_common.update(self.extract_dnp3_read_request(dnp3_object))
        elif feature_name == 'DIRECT OPERATE Request Data Objects':
            dnp3_object_common.update(self.extract_dnp3_direct_operate(dnp3_object))
        return dnp3_object_common

    def extract_dnp3_response(self, dnp3_object):
        count = 0
        obj_list = []
        for okey, value in dnp3_object.items():
            if 'dnp3.al.obj_tree' in okey:
                count += len(value.keys()) - 2
                dnp_obj_tree = value
                try:
                    objects = int(''.join(
                        [key.split(":")[-1] for key, val in dnp_obj_tree.items() if 'Point Number' in key]).replace(" ",""),2)
                except ValueError:
                    for key, val in dnp_obj_tree.items():
                        if 'Point Number' in key:
                            contents = re.findall('\[(.*?)\]', key)
                            target_point = [int(s) for s in key.split() if s.isdigit()]
                            if len(target_point) == 0:
                                objects = None
                            else:
                                objects = target_point[0]
            elif "dnp3.al.obj" in okey:
                obj_list.append(dnp3_object["dnp3.al.obj"])
        return {'DNP3 Objects': str(objects), 'DNP3 Object Count': str(count), 'AL_dnp3_obj': obj_list}

    def extract_dnp3_read_request(self, dnp3_object):
        count = len(list(dnp3_object.keys())) / 2
        objects = 0
        obj_list = []
        for okey, value in dnp3_object.items():
            if 'dnp3.al.obj_tree' in okey:
                dnp_obj_tree = value
                objects += len([str(val) for key, val in dnp_obj_tree.items() if 'Qualifier Field' in key])
            elif "dnp3.al.obj" in okey:
                obj_list.append(dnp3_object["dnp3.al.obj"])
        return {'DNP3 Objects': str(objects), 'DNP3 Object Count': str(count), 'AL_dnp3_obj': obj_list}

    def extract_dnp3_direct_operate(self, dnp3_object):
        count = 0
        # obtain the DNP3 control codes
        objects = 0
        obj_list = []
        for okey, value in dnp3_object.items():
            if 'dnp3.al.obj_tree' in okey:
                count += len(value.keys())
                dnp_obj_tree = value
                for key, val in dnp_obj_tree.items():
                    if 'Point Number' in key:
                        for subkey, subvalue in val.items():
                            if 'Control Code' in subkey:
                                contents = re.findall('\[(.*?)\]', subkey)
                                objects += int(contents[0], 16)
            elif "dnp3.al.obj" in okey:
                obj_list.append(dnp3_object["dnp3.al.obj"])
        return {'DNP3 Objects': str(objects), 'DNP3 Object Count': str(count), 'AL_dnp3_obj': obj_list}

    def extract_cyber_data(self):
        feature_list = ['frame.len', 'frame.protocols',
                        'eth.src', 'eth.dst',
                        'ip.src', 'ip.dst', 'ip.len', 'ip.flags',
                        'tcp.srcport', 'tcp.dstport', 'tcp.len', 'tcp.flags','tcp.nxtseq','tcp.ack']
        self.cyber_table = pd.DataFrame(columns=['Time'] + feature_list)
        cyber_total_selections = []

        for single_record in self.rawdata:
            if 'ospf' in single_record[u'_source'][u'layers'][u'frame'][u'frame.protocols']:
                continue
            cyber_record_selections = dict()
            cyber_record_selections.setdefault('Time', single_record['_source']['layers']['frame']['frame.time_epoch'])
            for name in feature_list:
                layer_name = name.split('.')[0]
                try:
                    cyber_record_selections.setdefault(name, single_record['_source']['layers'][layer_name][name])
                except:
                    pass
            cyber_total_selections.append(cyber_record_selections)
        self.cyber_table = self.cyber_table.append(cyber_total_selections)
        return self.cyber_table

    def connect_to_elasticsearch(self, ip, port: int = 9200):
        self.packetbeat = Elasticsearch([{'host': ip, 'port': port}])

    def retrieve_packetbeat(self, json_body, size=10000):
        try:
            self.packetbeat_response = self.packetbeat.search(body=json_body, index="packetbeat-*", size=10000)
        except ConnectionError:
            print('Elasticsearch is not connected')

    def extract_packetbeat(self):
        feature_list = ['destination.ip', 'destination.port', 'destination.mac', 'destination.packets',
                        'destination.bytes'
                        'source.ip', 'source.port', 'source.mac', 'source.packets', 'source.bytes',
                        'flow.id', 'flow.final', 'flow.duration', 'source.stats.net_packets_total',
                        'source.stats.net_bytes_total',
                        'destination.stats.net_packets_total', 'destination.stats.net_bytes_total', 'event.end',
                        'event.start']
        self.pb_table = pd.DataFrame(columns=['Time'] + feature_list)
        pb_total_selections = []

        for single_response in self.packetbeat_response['hits']['hits']:
            pb_record_selections = dict()
            pb_record_selections.setdefault('Time', single_response['_source']['event']['end'])
            for name in feature_list:
                attributes = name.split('.')
                try:
                    if (len(attributes) == 2):
                        pb_record_selections.setdefault(name, single_response['_source'][attributes[0]][attributes[1]])
                    elif (len(attributes) == 3):
                        pb_record_selections.setdefault(name, single_response['_source'][attributes[0]][attributes[1]][
                            attributes[2]])
                    else:
                        pb_record_selections.setdefault(name, single_response['_source'][attributes[0]])
                except:
                    pass
            pb_total_selections.append(pb_record_selections)
        self.pb_table = self.pb_table.append(pb_total_selections)
        self.pb_table['Time'] = pd.to_datetime(self.pb_table['Time'])
        return self.pb_table

    def merge_packetbeat(self):
        cyber_table = self.cyber_table
        cyber_table['Time'] = cyber_table['Time'].astype('float')
        for new_column in ['flow.count', 'flow.final_count', 'packets']:
            cyber_table[new_column] = 0
        # self.pb_table['Time'] = self.pb_table['Time'].dt.to_pydatetime()
        # self.pb_table['Time'] = self.pb_table['Time'].tz_convert(tz='UTC')
        # find the index for the rows within the time range

        self.pb_table['Time'] = self.pb_table['Time'].astype('int64') / 10e8
        self.pb_table['event.start'] = pd.to_datetime(self.pb_table['event.start']).astype('int64') / 10e8
        self.pb_table['event.end'] = pd.to_datetime(self.pb_table['event.end']).astype('int64') / 10e8
        # self.pb_table['Time'] = self.pb_table['Time'].astype('str')
        # print(self.pb_table['Time'])
        mask = (self.pb_table['Time'] >= cyber_table['Time'].iloc[0]) & (
                    self.pb_table['Time'] <= cyber_table['Time'].iloc[-1])
        selection = self.pb_table.loc[mask]
        row_count = len(cyber_table.index)
        for _, row in selection.iterrows():
            start, end, final, packets = row['event.start'], row['event.end'], row['flow.final'], row['source.packets']
            for index, cyber_rows in cyber_table.iterrows():
                # print(type(cyber_rows['Time']), cyber_rows['Time'])
                # print(type(start), start)
                if index != row_count - 1:
                    # print(start, end, final, packets)
                    # print(cyber_rows['Time'], cyber_table.at[index+1, 'Time'])
                    if (cyber_rows['Time'] <= start and cyber_table.at[index + 1, 'Time'] >= start) or (
                            cyber_rows['Time'] <= end and cyber_table.at[index + 1, 'Time'] >= end) or (
                            cyber_rows['Time'] >= start and cyber_table.at[index + 1, 'Time'] <= end):
                        cyber_table.loc[index + 1, 'flow.count'] += 1
                        cyber_table.loc[index + 1, 'packets'] += packets
                        if final: cyber_table.loc[index + 1, 'flow.final_count'] += 1
                        # cyber_table.iloc[[index+1]]['packets'] += packets
                        # if final: cyber_table.iloc[[index+1]]['flow.final_count'] += 1
        cyber_table['Time'] = cyber_table['Time'].astype('str')
        for index, row in cyber_table.iterrows():
            cyber_table.loc[index, 'Time'] += '0'*(9-len(row['Time'].split('.')[1]))
        # cyber_table['Time'] = cyber_table['Time'].astype('str')
        self.cyber_table = cyber_table
        return cyber_table

    def extract_snort(self, path):
        reader = unified2.FileRecordReader(path)
        record_list = [record for record in reader]
        snort_table = pd.DataFrame(record_list)
        snort_table['Time'] = snort_table.apply(lambda row: str(int(row['packet-second']) + int(row['packet-microsecond'])/float(1000000)),
                                                axis=1)
        if self.snort_table is None:
            self.snort_table = snort_table
        else:
            self.snort_table = self.snort_table.merge(snort_table, how='inner')
        return self.snort_table


    def process_snort(self,file_name):
        alert_types = ['DNP3', 'flood', 'arpspoof']
        total_records = []
        f = open(file_name, 'r')
        data = f.read()
        alerts = data.split('\n\n')
        date_pattern = "((?:[0-9]{2}[-\/:.]){5}[0-9]{6})"
        for alert in alerts[:-1]:
            time = re.search(date_pattern, alert).group(0)
            unix_time = datetime.datetime.strptime('20/' + time, '%y/%m/%d-%H:%M:%S.%f').timestamp()
            # if alert_type in alert.split('[**]')[1]:
            try:
                total_records.append({'message': alert.split('[**]')[1], 'Time': unix_time,
                                      'Alert Type': [al for al in alert_types if al in alert.split('[**]')[1]][0]})
            except:
                pass
        self.snort_table = pd.DataFrame(total_records)
        return self.snort_table

    def imputate(self, replace_map):
        self.merged_table = self.merged_table.fillna(value=replace_map)
        return self.merged_table

    def encode(self, encoding_list):
        from sklearn.preprocessing import LabelEncoder
        encoder_list = []
        for feature in encoding_list:
            encoder = LabelEncoder()
            encoder.fit(self.merged_table[feature].astype('str'))
            self.merged_table[feature] = pd.DataFrame(encoder.transform(self.merged_table[feature].astype('str')))
            encoder_list.append({'feature': feature, 'encoder': encoder})
        self.encoder_list = encoder_list
        return self.merged_table

    def decode(self, encoding_list):
        from sklearn.preprocessing import LabelEncoder
        for feature in encoding_list:
            container = next(item for item in self.encoder_list if item["feature"] == feature)
            temp_list = container.encoder.inverse_transform(self.merged_table[feature])
            self.merged_table[feature] = pd.DataFrame(temp_list)
        return self.merged_table

    def merge_snort(self):
        self.cyber_table['snort_alert'] = 0
        self.cyber_table['snort_alert_type'] = np.nan
        for index, row in self.snort_table.iterrows():
            if self.cyber_table.loc[0, 'Time'] < str(row['Time']) < self.cyber_table['Time'].iloc[-1]:
                series = self.cyber_table['Time'] < str(row['Time'])
                nearest_index = list(self.cyber_table[series].index)[-1]
                # print(nearest_index, row['Time'])
                # print(self.cyber_table[series]['Time'])
                self.cyber_table.loc[nearest_index, 'snort_alert'] = 1
                if 'DNP3' in row['message']:
                    self.cyber_table.loc[nearest_index, 'snort_alert_type'] = row['Alert Type']
                elif 'arpspoof' in row['message']:
                    self.cyber_table.loc[nearest_index, 'snort_alert_type'] = row['Alert Type']
                elif 'flood' in row['message']:
                    self.cyber_table.loc[nearest_index, 'snort_alert_type'] = row['Alert Type']
                else:
                    self.cyber_table.loc[nearest_index, 'snort_alert_type'] = 'general'
        return self.cyber_table

    def merge_lazy(self):
        self.physical_table['Time'] = pd.to_datetime(self.physical_table['Time'], unit='s')
        self.cyber_table['Time'] = pd.to_datetime(self.cyber_table['Time'], unit='s')
        self.merged_table = self.cyber_table.merge(self.physical_table, how='inner')
        return self.merged_table

    def merge(self, location=None, epoch=False, by_time=False, table_list: list or None = None):
        if by_time:
            output = self.merge_by_time(table_list)
        else:
            output = self.merge_by_location(location, epoch)
        return output

    def merge_by_pcap(self):
        if self.cyber_table['Time'].duplicated().any():
            if self.cyber_table['Time'].equals(self.pcap_table['Time']):
                self.cyber_table = self.cyber_table.merge(self.pcap_table, left_index=True, right_index=True)
                self.cyber_table = self.cyber_table.rename(columns={"Time_x": "Time"})
                self.cyber_table = self.cyber_table.drop(columns=["Time_y"])
            else:
                raise Exception('Cannot be merged')
        else:
            self.cyber_table = self.cyber_table.merge(self.pcap_table, how='inner')
        return self.cyber_table

    def merge_by_location(self, location=None, epoch=False):
        if self.physical_table is None:
            self.extract_physical_data()
        if self.cyber_table is None:
            self.extract_cyber_data()
        if self.cyber_table['Time'].duplicated().any():
            if self.cyber_table['Time'].equals(self.physical_table['Time']):
                self.merged_table = self.cyber_table.merge(self.physical_table, left_index = True, right_index = True)
                self.merged_table = self.merged_table.rename(columns={"Time_x": "Time"})
                self.merged_table = self.merged_table.drop(columns=["Time_y"])
            else:
                raise Exception('Cannot be merged')
        else:
            # self.merged_table = self.cyber_table.merge(self.physical_table, how='inner')
            self.merged_table = self.cyber_table.merge(self.physical_table, left_index=True, right_index=True)
            self.merged_table = self.merged_table.rename(columns={"Time_y": "Time"})
            self.merged_table = self.merged_table.drop(columns=["Time_x"])
        if location:
            self.merged_table['location'] = location
        if not epoch:
            self.merged_table['Time'] = pd.to_datetime(self.merged_table['Time'], unit='s')
        return self.merged_table

    def merge_by_time(self, table_list: list, location_list: list):
        if len(table_list) == len(location_list):
            merged = table_list[0]
            merged['location'] = location_list[0]
            for table, location in zip(table_list[1:], location_list[1:]):
                temp = table
                temp['location'] = location
                merged = merged.append(temp)
            print(merged)
            # merged = merged.sort_values(by=['Time'])
        else:
            raise Exception('The table list does not match the location list.')
        return merged

    def data_to_csv(self, path, target="merged", sanddance=False):
        target_table = None
        if target == "merged":
            target_table = self.merged_table
        elif target == "physical":
            target_table = self.physical_table
        elif target == "cyber":
            target_table = self.cyber_table
        if sanddance:
            name_list = [(name, name.replace('.', '_')) for name in list(target_table.columns)]
            target_table = target_table.rename(columns=dict(name_list))
        target_table.to_csv(path)
        return None

    def reset(self):
        self.source = None
        self.rawdata = None
        self.physical_table = None
        self.cyber_table = None
        self.merged_table = None

