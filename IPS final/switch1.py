from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

from ryu.lib.packet import in_proto
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import arp

from models import Session, Packets_dropped, History

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.dropped_packets = 0  # Initialize counter for dropped packets

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle=0, hard=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    idle_timeout=idle, hard_timeout=hard,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    idle_timeout=idle, hard_timeout=hard,
                                    match=match, instructions=inst)
            
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        # if packet is destined to be flooded, do not install a flow rule
        if out_port != ofproto.OFPP_FLOOD:
            # check IP Protocol and create a match for IP
            if eth.ethertype == ether_types.ETH_TYPE_IP:
                ip = pkt.get_protocol(ipv4.ipv4)
                srcip = ip.src
                dstip = ip.dst
                protocol = ip.proto

                # if ICMP Protocol
                if protocol == in_proto.IPPROTO_ICMP:
                    srcport = dstport = 0
                    proto = 'icmp'
                    t = pkt.get_protocol(icmp.icmp)
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                            ipv4_src=srcip, ipv4_dst=dstip,
                                            ip_proto=protocol, icmpv4_code=t.code,
                                            icmpv4_type=t.type)

                #  if TCP Protocol
                elif protocol == in_proto.IPPROTO_TCP:
                    proto = 'tcp'
                    t = pkt.get_protocol(tcp.tcp)
                    srcport = t.src_port
                    dstport = t.dst_port
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                            ipv4_src=srcip, ipv4_dst=dstip,
                                            ip_proto=protocol,
                                            tcp_src=srcport, tcp_dst=dstport, tcp_flags=t.bits)

                #  If UDP Protocol
                elif protocol == in_proto.IPPROTO_UDP:
                    proto = 'udp'
                    u = pkt.get_protocol(udp.udp)
                    srcport = u.src_port
                    dstport = u.dst_port
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                            ipv4_src=srcip, ipv4_dst=dstip,
                                            ip_proto=protocol,
                                            udp_src=u.src_port, udp_dst=u.dst_port,)
                
                attackers = self.get_attackers()
                attacked_ports = self.get_attacked_ports()
                banned_protocols = self.get_banned_protocols()
                
                if attackers and (str(srcip) in attackers or str(dstip) in attackers):
                    #print("Attackers", attackers)
                    actions = []
                    print("IP is banned.")
                    
                elif attacked_ports and (srcport in attacked_ports or dstport in attacked_ports):
                    #print("Ports", attacked_ports)
                    actions = []
                    print("You cannot communicate with this port.")
                    
                elif banned_protocols and proto in banned_protocols:
                    #print("Protocols", banned_protocols)
                    actions = []
                    print(f"Protocol {proto} is stopped.")
                    
                # Increment dropped packet counter if actions list is empty
                if not actions:
                    self.dropped_packets += 1
                    if self.dropped_packets >= 40:
                        self.update_dropped_packet_count()
                        self.dropped_packets = 0  # Reset counter

                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions, msg.buffer_id, idle=60, hard=120)
                    return
                else:
                    self.add_flow(datapath, 1, match, actions, idle=60, hard=120)

            elif eth.ethertype == ether_types.ETH_TYPE_ARP:
                ar = pkt.get_protocol(arp.arp)
                srcIp = ar.src_ip
                dstIp = ar.dst_ip
                srcMac = ar.src_mac
                dstMac = ar.dst_mac
                opcode = ar.opcode
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP,
                                        arp_op=opcode, arp_spa=srcIp,
                                        arp_tpa=dstIp, arp_sha=srcMac, arp_tha=dstMac)
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions, msg.buffer_id, idle=60, hard=140)
                    return
                else:
                    self.add_flow(datapath, 1, match, actions, idle=60, hard=140)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def update_dropped_packet_count(self):
        session = Session()
        try:
            packet_count_entry = session.query(Packets_dropped).first()
            if packet_count_entry:
                packet_count_entry.Count += 40
            else:
                # Create a new entry if it doesn't exist
                new_entry = Packets_dropped(Count=40)
                session.add(new_entry)
            
            session.commit()
        finally:
            session.close()

    def get_attackers(self):
        session = Session()
        try:
            return [entry.Attacker for entry in session.query(History.Attacker).distinct().filter(History.Attacker != 'random').all()]
        finally:
            session.close()

    def get_attacked_ports(self):
        session = Session()
        try:
            return [entry.Port for entry in session.query(History.Port).filter(History.Attacker == 'random').distinct().all()]
        finally:
            session.close()

    def get_banned_protocols(self):
        session = Session()
        try:
            return [entry.Protocole for entry in session.query(History.Protocole).filter(History.Protocole == 'icmp').distinct().all()]
        finally:
            session.close()

