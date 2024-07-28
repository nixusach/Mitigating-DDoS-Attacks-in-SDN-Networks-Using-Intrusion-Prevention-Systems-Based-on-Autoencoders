import switch1
from collections import Counter
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
import pandas as pd
from datetime import datetime
from models import Packet, Session, History
from keras.models import load_model
import pickle
import numpy as np
from sklearn.preprocessing import StandardScaler, MinMaxScaler

model_tcp = load_model('tcp.h5')
model_udp = load_model('udp.h5')
model_icmp = load_model('icmp.h5')
with open('RF.pkl', 'rb') as f:
    model_rf = pickle.load(f)

with open('std_icmp.pkl', 'rb') as f:
    scaler_icmp= pickle.load(f)

with open('std_tcp.pkl', 'rb') as f:
    scaler_tcp= pickle.load(f)

# class CollectTrainingStatsApp(simple_switch_13.SimpleSwitch13):
class CollectTrainingStatsApp(switch1.SimpleSwitch13):
    def __init__(self, *args, **kwargs):
        super(CollectTrainingStatsApp, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self.monitor)
        self.packets_tcp = []
        self.packets_udp = []
        self.packets_icmp = []
        self.session = Session()
        self.dictionnaire = {}


    @set_ev_cls(ofp_event.EventOFPStateChange,[MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath

        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def monitor(self):
        while True:
            for dp in self.datapaths.values():
                self.request_stats(dp)
            hub.sleep(10)


    def request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)        
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):

        timestamp = datetime.now()
        timestamp = timestamp.timestamp()
        m = {0: 'SLOWLORIS', 1: 'ICMP flood', 2: 'LAND attack', 3: 'HTTP flood', 4: 'SYN flood', 5: 'UDP flood'}

        body = ev.msg.body

        for stat in sorted([flow for flow in body if (flow.priority == 1) ], key=lambda flow:
            (flow.match['eth_type'])):
            if stat.match['eth_type'] == 0x0800 :
                ip_proto = stat.match['ip_proto']

                packet_data = self.process_flow_stats(stat, ip_proto)
                if packet_data['Ip_protocole']=='icmp':
                    self.packets_icmp.append(packet_data)
                if packet_data['Ip_protocole']=='tcp':
                    self.packets_tcp.append(packet_data)
                if packet_data['Ip_protocole']=='udp':
                    self.packets_udp.append(packet_data)
                
                if len(self.packets_icmp) >= 30:
                    Traffic = 'Normal' ; attack_type = '';
                    packets_to_save = self.packets_icmp[:30]
                    df = pd.DataFrame(packets_to_save)
                    num = ['Port_dst', 'Icmp','Icmp_type', 'Tcp', 'ACK', 'PSH', 'RST', 'SYN',
                    'FIN', 'Http', 'SSL', 'SSH', 'Ftp', 'Udp','Dns','Dhcp', 'Flow_duration',        
                    'Packet_count', 'Same_ip', 'Bytes']
                    X_test = df[num]

                    num=["Flow_duration","Packet_count","Bytes",'Icmp_type']
                    scaler = scaler_icmp
                    X_test_copy = X_test.copy()
                    X_test_copy.loc[:, num] = scaler.transform(X_test_copy.loc[:, num])

                    X_test_array = X_test_copy.values.astype(np.float32)  # Ensure data type is float32
                    loss, accuracy = model_icmp.evaluate(X_test_array, X_test_array)
                    print(f"RMSE ICMP: {np.sqrt(loss)}")

                    if np.sqrt(loss) > 0.279:
                        Traffic = 'Attack'
                        print('Attack')
                        dp = self.traitement_class(df)
                        y = model_rf.predict(dp)

                        y = [m[pred] for pred in y]
                        attack_type = Counter(y).most_common(1)[0][0]

                        print("Attack type:", attack_type)
                        if df['Ip_src'].nunique() == len(df):
                            src_att = 'random'
                            print("Attacker is: ", src_att)
                        else:   
                            src_att = df['Ip_src'].value_counts().idxmax()
                            print("Attacker is:", src_att)

                        port_att = 0
                        dst_att = df['Ip_dst'].value_counts().idxmax()
                        print("Attack destination port:", port_att)

                        timestamp_att = datetime.now()
                        timestamp_att = timestamp_att.timestamp()
                        self.add_to_history(timestamp_att,attack_type,src_att,dst_att,port_att, 'icmp')


                    else:
                        Traffic = 'Normal' ; attack_type = '';
                        print('Traffic nrml')

                    for packet_data in packets_to_save:
                        self.add_to_packet(packet_data, 'icmp', Traffic, attack_type)
                        self.packets_icmp = self.packets_icmp[30:]


                if len(self.packets_tcp) >= 30:
                    Traffic = 'Normal' ; attack_type = '';
                    packets_to_save = self.packets_tcp[:30]
                    df = pd.DataFrame(packets_to_save)
                    num = ['Port_dst', 'Icmp','Tcp', 'ACK', 'PSH', 'RST', 'SYN',
                    'FIN', 'Http', 'SSL', 'SSH', 'Ftp', 'Udp','Flow_duration','Packet_count',
                        'Same_ip', 'Bytes']
                    X_test = df[num]
                    X_test.loc[:, 'Port_dst'] = X_test['Port_dst'].apply(self.filter_port)
                    scaler = scaler_tcp
                    num=["Flow_duration","Packet_count","Bytes",'Port_dst']
                    X_test_copy = X_test.copy()
                    X_test_copy.loc[:, num] = scaler.transform(X_test_copy.loc[:, num])

                    X_test_array = X_test_copy.values.astype(np.float32) 
                    loss, accuracy = model_tcp.evaluate(X_test_array, X_test_array)
                    print(f"RMSE TCP: {np.sqrt(loss)}")
                    if np.sqrt(loss) > 0.09:
                        Traffic = 'Attack'
                        print('Attack')
                        dp = self.traitement_class(df)
                        y = model_rf.predict(dp)
                        y = [m[pred] for pred in y]
                        attack_type = Counter(y).most_common(1)[0][0]

                        print("Attack type:", attack_type)
                        if df['Ip_src'].nunique() == len(df):
                            src_att = 'random'
                            print("Attacker is: ", src_att)
                        else:   
                            src_att = df['Ip_src'].value_counts().idxmax()
                            print("Attacker is:", src_att)

                        port_att = df['Port_dst'].value_counts().idxmax()
                        dst_att = df['Ip_dst'].value_counts().idxmax()
                        print("Attack destination port:", port_att)

                        timestamp_att = datetime.now()
                        timestamp_att = timestamp_att.timestamp()
                        self.add_to_history(timestamp_att,attack_type,src_att,dst_att,str(port_att),'tcp')
                    else:
                        Traffic = 'Normal' ; attack_type = '';
                        print('Traffic nrml')

                    for packet_data in packets_to_save:
                        self.add_to_packet(packet_data, 'tcp', Traffic, attack_type)
                        self.packets_tcp = self.packets_tcp[30:]


                if len(self.packets_udp) >= 30:
                    packets_to_save = self.packets_udp[:30]
                    df = pd.DataFrame(packets_to_save)
                    num = ['Port_dst', 'Icmp','Icmp_type','Icmp_code', 'Tcp', 'ACK', 'PSH', 'RST', 'SYN',
                    'FIN', 'Http', 'SSL', 'SSH', 'Ftp', 'Udp','Dns','Dhcp', 'Flow_duration',        
                    'Packet_count', 'Same_ip', 'Bytes']
                    X_test = df[num]
                    X_test.loc[:, 'Port_dst'] = X_test['Port_dst'].apply(self.filter_port)
                    scaler = MinMaxScaler()
                    num=["Flow_duration","Packet_count","Bytes",'Port_dst']
                    scaler.fit(X_test.loc[:, num])
                    X_test_copy = X_test.copy()
                    X_test_copy.loc[:, num] = scaler.transform(X_test_copy.loc[:, num])

                    X_test_array = X_test_copy.values.astype(np.float32) 
                    loss, accuracy = model_udp.evaluate(X_test_array, X_test_array)
                    print(f"RMSE UDP: {np.sqrt(loss)}")
                    if np.sqrt(loss) > 0.16:
                        Traffic = 'Attack'
                        print('Attack')
                        dp = self.traitement_class(df)
                        y = model_rf.predict(dp)
                        y = [m[pred] for pred in y]
                        attack_type = Counter(y).most_common(1)[0][0]

                        print("Attack type:", attack_type)
                        if df['Ip_src'].nunique() == len(df):
                            src_att = 'random'
                            print("Attacker is: ", src_att)
                        else:   
                            src_att = df['Ip_src'].value_counts().idxmax()
                            print("Attacker is:", src_att)

                        port_att = df['Port_dst'].value_counts().idxmax()
                        dst_att = df['Ip_dst'].value_counts().idxmax()
                        print("Attack destination port:", port_att)

                        timestamp_att = datetime.now()
                        timestamp_att = timestamp_att.timestamp()
                        self.add_to_history(timestamp_att,attack_type,src_att,dst_att,port_att,'udp')
                    else:
                        Traffic = 'Normal' ; attack_type = '';
                        print('Traffic nrml')
                    for packet_data in packets_to_save:
                        #self.add_to_packet(packet_data, 'udp', Traffic, attack_type)
                        self.packets_udp = self.packets_udp[30:]
                        

    def filter_port(self, port):
        ports = [21, 22, 53, 80, 443,0]
        if port not in ports:
            return 0
        else:
            return port
        
    def process_flow_stats(self, stat, ip_proto):
        timestamp = datetime.now().timestamp()
        icmp, tcp, udp, http, dns, ssl, ftp, ssh, dhcp = (0, 0, 0, 0, 0, 0, 0, 0, 0)
        ACK, PSH, RST, SYN ,FIN = (0, 0, 0, 0, 0)
        ipp = ""; ipp_type=""; 
        if stat.match.get('ipv4_src')==stat.match.get('ipv4_dst'):
            same_ip = 1;
        else:
            same_ip = 0

        if ip_proto == 1:
            ipp = 'icmp';
            port_src, port_dst = (-1, -1)
            icmp = 1
            icmp_code = stat.match['icmpv4_code']
            icmp_type = stat.match['icmpv4_type']

        elif ip_proto == 6:
            icmp_code, icmp_type = (-1, -1)
            ipp = 'tcp';
            tcp = 1
            port_src = stat.match['tcp_src']
            port_dst = stat.match['tcp_dst']
            if port_dst == 80 or port_src == 80:
                http = 1; ipp_type="Http"
            elif port_dst == 443 or port_src == 443:
                ssl = 1; ipp_type="SSL"
            elif port_dst == 21 or port_dst == 20 or port_src == 21 or port_src == 20:
                ftp = 1; ipp_type="Ftp"
            elif port_dst == 22 or port_src == 22:
                ssh = 1; ipp_type="SSH"

            tcp_flags = stat.match['tcp_flags'];
            flags_bin = bin(tcp_flags)[2:]
            flags_bin = flags_bin.zfill(9)
            control = {0: 'NS', 1: 'WCR', 2: 'ECE', 3: 'URG', 4: 'ACK', 5: 'PSH', 6: 'RST', 7: 'SYN', 8: 'FIN'}
            flags = {}
            for i, bit in enumerate(flags_bin):
                flags[control[i]] = bit
            ACK = flags['ACK']
            PSH = flags['PSH']
            RST = flags['RST']
            SYN = flags['SYN']
            FIN = flags['FIN']

        elif ip_proto == 17:
            icmp_code, icmp_type = (-1, -1)
            ipp = 'udp';
            udp = 1
            port_src = stat.match['udp_src']
            port_dst = stat.match['udp_dst']
            if port_src == 53 or port_dst == 53:
                dns = 1; ipp_type="DNS"
            elif port_dst == 67 or port_dst == 68 or port_src == 67 or port_src == 68:
                dhcp = 1; ipp_type="Dhcp"
        
        try:
            pkt_per_sec = stat.packet_count / stat.duration_sec
            pkt_per_nsec = stat.packet_count / stat.duration_nsec
        except ZeroDivisionError:
            pkt_per_sec = 0
            pkt_per_nsec = 0
        
        try:
            bytes_per_sec = stat.byte_count / stat.duration_sec
            bytes_per_nsec = stat.byte_count / stat.duration_nsec
        except ZeroDivisionError:
            bytes_per_sec = 0
            bytes_per_nsec = 0

        packet_data = {
            'Timestamp': timestamp,
            'Ip_src': stat.match.get('ipv4_src', ''),
            'Ip_dst': stat.match.get('ipv4_dst', ''),
            'Same_ip': same_ip,
            'Port_src': port_src,
            'Port_dst': port_dst,
            'Ip_protocole': ipp,
            'Type_protocole': ipp_type,
            'Icmp': icmp,
            'Icmp_code': icmp_code,
            'Icmp_type': icmp_type,
            'Tcp': tcp,
            'SYN': SYN,
            'ACK': ACK,
            'PSH': PSH,
            'RST': RST,
            'FIN': FIN,
            'Http': http,
            'SSL': ssl,
            'SSH': ssh,
            'Ftp': ftp,
            'Udp': udp,
            'Dns': dns,
            'Dhcp': dhcp,
            'Flow_duration': stat.duration_sec,
            'Flow_dur_nsec': stat.duration_nsec,
            'Packet_count': stat.packet_count,
            'Pkt_per_sec': pkt_per_sec,
            'Pkt_per_nsec': pkt_per_nsec,
            'Bytes': stat.byte_count,
            'Bytes_per_sec': bytes_per_sec,
            'Bytes_per_nsec': bytes_per_nsec
        }
        return packet_data

    def traitement_class(self, df):
        num = ['Port_dst', 'Icmp', 'Tcp', 'ACK', 'PSH', 'RST', 'SYN', 'FIN', 'Http','SSH',
                'Ftp', 'Udp', 'Flow_duration', 'Flow_dur_nsec', 'Packet_count',
                'Pkt_per_sec', 'Same_ip']

        df = df[num]
        df.loc[:, 'Port_dst'] = df['Port_dst'].apply(self.filter_port)
        
        scaler = MinMaxScaler()
        num=["Pkt_per_sec","Flow_dur_nsec",'Port_dst']
        scaler.fit(df[num])
        df.loc[:, num] = scaler.transform(df[num])

        scaler = StandardScaler()
        num=["Flow_duration","Packet_count"]
        scaler.fit(df[num])
        df.loc[:, num] = scaler.transform(df[num])
        return df


    def add_to_history(self,timestamp_att,attack_type,src_att,dst_att,port_att,protocole):
        my_history = {'Timestamp': timestamp_att,
                      'Attack_type': attack_type,
                      'Attacker': src_att,
                      'Victim': dst_att,
                      'Port': port_att,
                      'Action' : '',
                      'Protocole' : protocole}
        tcp_history = History(**my_history)
        self.session.add(tcp_history)
        self.session.commit()
        self.session.close()

    def add_to_packet(self, packet_data, protocole, Traffic, attack_type):
        my_packet = {'Timestamp': packet_data['Timestamp'],
                     'Ip_src': packet_data['Ip_src'],
                     'Ip_dst': packet_data['Ip_dst'],
                     'Port_src': packet_data['Port_src'],
                     'Port_dst': packet_data['Port_dst'],
                     'Ip_protocole' : protocole,
                     'Type_protocole' : packet_data['Type_protocole'],
                     'Icmp_type' : packet_data['Icmp_type'],
                     'Flow_duration' : packet_data['Flow_duration'],
                     'Packet_count' : packet_data['Packet_count'],
                     'Byte_count' : packet_data['Bytes'],
                     'Traffic' : Traffic,
                     'Attack_type' : attack_type}
                        
        tcp_packet = Packet(**my_packet)
        self.session.add(tcp_packet)
        self.session.commit()
        self.session.close()

