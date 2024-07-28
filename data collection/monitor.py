import simple_switch
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub

from datetime import datetime

# class CollectTrainingStatsApp(simple_switch_13.SimpleSwitch13):
class CollectTrainingStatsApp(simple_switch.SimpleSwitch13):
    def __init__(self, *args, **kwargs):
        super(CollectTrainingStatsApp, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self.monitor)

        with open("flow.csv", "w") as file:
            file.write('Timestamp,Datapath_id,Ip_src,Mac_src,Ip_dst,Mac_dst,Same_ip,Arp,Arp_code,Ip_protocole,Port_src,Port_dst,Icmp,Icmp_code,Icmp_type,Tcp,Tcp_flags,NS,WCR,ECE,URG,ACK,PSH,RST,SYN,FIN,Http,SSL,SSH,Ftp,Udp,Dns,Dhcp,Flow_duration,Flow_dur_nsec,Packet_count,Pkt_per_sec,Pkt_per_nsec,Bytes,Bytes_per_sec,Bytes_per_nsec,Hard_timeout,Idle_timeout,Attack,Attack_type\n')

    #Asynchronous message
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

        file = open("flow.csv","a+")
        body = ev.msg.body
        for stat in sorted([flow for flow in body if (flow.priority == 1) ], key=lambda flow:
            (flow.match['eth_type'])):
            if stat.match['eth_type'] == 0x0800 :
                ip_src = stat.match['ipv4_src']
                ip_dst = stat.match['ipv4_dst']
                icmp = 0; tcp = 0; udp = 0; http = 0; dns = 0; ssl = 0; ftp = 0; ssh = 0; dhcp = 0;
                NS,WCR,ECE,URG,ACK,PSH,RST,SYN,FIN = (0, 0, 0, 0, 0, 0, 0, 0, 0);
                icmp_code, icmp_type = (-1, -1)
                port_src = 0; port_dst = 0;
                tcp_flags = 0;
                if ip_src==ip_dst:
                    same_ip = 1
                else:
                    same_ip = 0

                if stat.match['ip_proto'] == 1:
                    icmp = 1
                    icmp_code = stat.match['icmpv4_code']
                    icmp_type = stat.match['icmpv4_type']

                elif stat.match['ip_proto'] == 6:
                    tcp = 1;
                    port_src = stat.match['tcp_src']
                    port_dst = stat.match['tcp_dst']

                    tcp_flags = stat.match['tcp_flags'];
                    flags_bin = bin(tcp_flags)[2:]
                    flags_bin = flags_bin.zfill(9)
                    control = {0: 'NS', 1: 'WCR', 2: 'ECE', 3: 'URG', 4: 'ACK', 5: 'PSH', 6: 'RST', 7: 'SYN', 8: 'FIN'}
                    flags = {}
                    for i, bit in enumerate(flags_bin):
                        flags[control[i]] = bit
                    NS = flags['NS']
                    WCR = flags['WCR']
                    ECE = flags['ECE']
                    URG = flags['URG']
                    ACK = flags['ACK']
                    PSH = flags['PSH']
                    RST = flags['RST']
                    SYN = flags['SYN']
                    FIN = flags['FIN']

                    if port_dst == 80 or port_src == 80:
                        http = 1;
                    elif port_dst == 443 or port_src == 443:
                        ssl = 1;
                    elif port_dst == 21 or port_dst == 20 or port_src == 21 or port_src == 20:
                        ftp = 1;
                    elif port_dst == 22 or port_src == 22:
                        ssh = 1;

                elif stat.match['ip_proto'] == 17:
                    udp = 1;
                    port_src = stat.match['udp_src']
                    port_dst = stat.match['udp_dst']
                    if port_src == 53 or port_dst == 53:
                        dns = 1;
                    elif port_dst == 67 or port_dst == 68 or port_src == 67 or port_src == 68:
                        dhcp = 1;
                
                try:
                    pkt_per_sec = stat.packet_count/stat.duration_sec
                    pkt_per_nsec = stat.packet_count/stat.duration_nsec
                except:
                    pkt_per_sec = 0
                    pkt_per_nsec = 0
                    
                try:
                    bytes_per_sec = stat.byte_count/stat.duration_sec
                    bytes_per_nsec = stat.byte_count/stat.duration_nsec
                except:
                    bytes_per_sec = 0
                    bytes_per_nsec = 0
                    
                file.write("{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n"
                    .format(timestamp, ev.msg.datapath.id, ip_src,'',ip_dst,'',same_ip,0,'',
                            stat.match['ip_proto'],port_src,port_dst,icmp,icmp_code,icmp_type,tcp,tcp_flags,
                            NS,WCR,ECE,URG,ACK,PSH,RST,SYN,FIN,http,ssl,ssh,ftp,udp,dns,dhcp,
                            stat.duration_sec, stat.duration_nsec,stat.packet_count,pkt_per_sec,pkt_per_nsec,
                            stat.byte_count,bytes_per_sec,bytes_per_nsec,
                            stat.hard_timeout, stat.idle_timeout,0,''))

            elif stat.match['eth_type'] == 0x0806 :
                if stat.match.get('arp_spa')==stat.match.get('arp_tpa'):
                    same_ip = 1
                else:
                    same_ip = 0
                try:
                    pkt_per_sec = stat.packet_count/stat.duration_sec
                    pkt_per_nsec = stat.packet_count/stat.duration_nsec
                except:
                    pkt_per_sec = 0
                    pkt_per_nsec = 0
                    
                try:
                    bytes_per_sec = stat.byte_count/stat.duration_sec
                    bytes_per_nsec = stat.byte_count/stat.duration_nsec
                except:
                    bytes_per_sec = 0
                    bytes_per_nsec = 0

                file.write("{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n"
                    .format(timestamp, ev.msg.datapath.id, stat.match.get('arp_spa'), stat.match.get('arp_sha'),
                            stat.match.get('arp_tpa'), stat.match.get('arp_tha'),same_ip, 1, stat.match.get('arp_op'),
                            '', '','', '', '', '', '', '', '','', '','', '', '',
                            '', '', '', '', '', '', '', '', '', '',
                            stat.duration_sec, stat.duration_nsec, stat.packet_count, pkt_per_sec, pkt_per_nsec,
                            stat.byte_count, bytes_per_sec, bytes_per_nsec,
                            stat.hard_timeout, stat.idle_timeout, 0, ''))

        file.close()
