from agent import Agent

from operator import attrgetter
import simple_switch_13

from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.lib.ip import ipv4_to_bin, ipv4_to_str
from ryu.lib import packet
from ryu.lib.mac import haddr_to_bin
import numpy as np 

class TrafficMonitor(simple_switch_13.SimpleSwitch13):

    def __init__(self, *args, **kwargs):
        super(TrafficMonitor, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.state = {}
        self.init_thread = hub.spawn(self._monitor)
        self.network_info = {"no_of_ports_per_switch": 3, "no_of_switches": 3}
        self.updated_port_count = 0
        self.unrolled_state = []
        self.input_state = []
        
        self.packet_count = {}
        self.attack_packet_count = {}
        
        self.reward = 0.0
        self.lambd = 0.9
        self.packet_count_dp_3 = 0


    # The event handler assiciated with this decorator is called on change of state in the network
    # i.e for eg: whenever a new switch is associated with the controller

    @set_ev_cls(ofp_event.EventOFPStateChange,[MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.state[datapath.id]=[]
                self.datapaths[datapath.id] = datapath
                self.packet_count[datapath.id] = 0
                self.attack_packet_count[datapath.id] = 0
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]
                del self.packet_count[datapath.id]
                del self.attack_packet_count[datapath.id]

    def _monitor(self):
        print("Initializing...")
        hub.sleep(10)
        while True:
            self.get_state()
            hub.sleep(2)
            self.update_attack_packet_count(self.datapaths[3])
            hub.sleep(2)
            self.format_state()
            self.add_meter(self.datapaths[3])
            

    # Request statistics associated with each switch (dp)
    def get_state(self):
        for dp in self.datapaths.values():
            self.send_flow_stats_request(dp)
            
    def send_flow_stats_request(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)    

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser 

        packet_count_n = 0
        byte_count_n = 0
        flow_count_n = 0

        # for stat in sorted([flow for flow in body if flow.priority == 1],
        #         key=lambda flow: (flow.match['in_port'], flow.match['eth_dst'])):
        for stat in ([flow for flow in body ]):
            print(str(stat))
            flow_count_n += 1
            packet_count_n += stat.packet_count
            byte_count_n += stat.byte_count

        if len(self.state[datapath.id]) == 0:
            self.state[datapath.id].append({})
            self.state[datapath.id].append(packet_count_n)
            self.state[datapath.id].append(byte_count_n)
            self.state[datapath.id].append(flow_count_n)
        else:
            self.state[datapath.id][1] = packet_count_n
            self.state[datapath.id][2] = byte_count_n
            self.state[datapath.id][3] = flow_count_n

        if(datapath.id == 3):
            self.packet_count[datapath.id] = packet_count_n
        
        for port_no in range(1, self.network_info["no_of_ports_per_switch"] + 1):
            req = parser.OFPPortStatsRequest(datapath, 0, port_no)
            datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body
        datapath = ev.msg.datapath
        temp=[]
        
        for stat in body:
            temp.append(str(stat.rx_packets))
            temp.append(str(stat.rx_bytes))
            temp.append(str(stat.tx_packets))
            temp.append(str(stat.tx_bytes))
            self.state[datapath.id][0][stat.port_no] = temp

    def format_state(self):
        curr_unrolled_state = []

        for key in self.state.keys():
            switch_data = self.state[key]
            if(switch_data):
                port_data, packet_count, byte_count, flow_count = switch_data[0], switch_data[1], switch_data[2], switch_data[3]

                for port in range(1, 1 + self.network_info['no_of_ports_per_switch']):
                    if port in port_data:
                        for val in port_data[port]:
                            curr_unrolled_state.append(val) 
                    else :
                        for i in range(0,4):
                            curr_unrolled_state.append(0) 
                
                curr_unrolled_state.append(packet_count)
                curr_unrolled_state.append(byte_count)
                curr_unrolled_state.append(flow_count)
        
        
        if(len(curr_unrolled_state) != 0):
            curr_unrolled_state = list(map(int, curr_unrolled_state))           
            iter_count = self.network_info['no_of_switches']*(self.network_info['no_of_ports_per_switch'] * 4 + 3)

            if(len(self.unrolled_state) != 0):
                prev_state = self.unrolled_state
            else:
                prev_state = [0]*iter_count
            
            temp_unrolled_state = [0]*iter_count

            for i in range(iter_count):
                try:
                    temp_unrolled_state[i] = curr_unrolled_state[i] - prev_state[i]
                except:
                    self.logger.info("Out of index error would have occured!")


            self.input_state = temp_unrolled_state
            self.unrolled_state = curr_unrolled_state
            self.get_reward(self.datapaths[3])

    def update_attack_packet_count(self, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        self.reward_flag = True
        cookie = cookie_mask = 0

        ip_src = "10.1.1.1"
        ip_dst = "10.0.0.4"
        
        match = ofp_parser.OFPMatch(eth_type = 0x0800, ipv4_src = ip_src)
        # match = ofp_parser.OFPMatch()
        req = ofp_parser.OFPAggregateStatsRequest(datapath, 0,ofp.OFPTT_ALL,ofp.OFPP_ANY,ofp.OFPG_ANY,cookie,cookie_mask, match)
        datapath.send_msg(req)
    
    @set_ev_cls(ofp_event.EventOFPAggregateStatsReply, MAIN_DISPATCHER)
    def aggregate_stats_reply_handler(self, ev):
        body = ev.msg.body
        datapath = ev.msg.datapath

        self.attack_packet_count[datapath.id] = body.packet_count

    def get_reward(self, datapath):
        # self.send_meter_stats_request(datapath)
        packets_in_network = sum(self.packet_count.values())
        attack_packets_in_network = sum(self.attack_packet_count.values())
        try:
            pass
            # print("Reward = " + str(self.attack_packet_count[3]) + " " + str(self.packet_count[3]))
        except:
            print("Some error while calculating reward!")

    def add_meter(self, datapath):
        # datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # bands = [parser.OFPMeterBandDrop(type_=ofproto.OFPMBT_DROP, len_=0, rate=100)]

        # req=parser.OFPMeterMod(datapath=datapath, command=ofproto.OFPMC_MODIFY, flags=ofproto.OFPMF_PKTPS, meter_id=1, bands=bands)
        # print(str(req))
        # datapath.send_msg(req)
        
        # match = parser.OFPMatch()
        # actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        
        # inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions),parser.OFPInstructionMeter(1)]
        # # print(str(inst))
        # mod = parser.OFPFlowMod(datapath=datapath, priority=1, match=match, instructions=inst)
        # datapath.send_msg(mod)

        self.send_meter_config_stats_request(datapath)

    def send_meter_stats_request(self, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        req = ofp_parser.OFPMeterStatsRequest(datapath, 0, ofp.OFPM_ALL)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPMeterStatsReply, MAIN_DISPATCHER)
    def meter_stats_reply_handler(self, ev):
        meters = []
        print(str(ev.msg.body))
        # for stat in ev.msg.body:
        #     meters.append('meter_id=0x%08x len=%d flow_count=%d '
        #                 'packet_in_count=%d byte_in_count=%d '
        #                 'duration_sec=%d duration_nsec=%d '
        #                 'band_stats=%s' %
        #                 (stat.meter_id, stat.len, stat.flow_count,
        #                 stat.packet_in_count, stat.byte_in_count,
        #                 stat.duration_sec, stat.duration_nsec,
        #                 stat.band_stats))
        # self.logger.info('MeterStats: %s', meters)

    def send_meter_config_stats_request(self, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        req = ofp_parser.OFPMeterConfigStatsRequest(datapath, 0,
                                                    ofp.OFPM_ALL)
        datapath.send_msg(req)        
    
    @set_ev_cls(ofp_event.EventOFPMeterConfigStatsReply, MAIN_DISPATCHER)
    def meter_config_stats_reply_handler(self, ev):
        configs = []
        for stat in ev.msg.body:
            configs.append('length=%d flags=0x%04x meter_id=0x%08x '
                        'bands=%s' %
                        (stat.length, stat.flags, stat.meter_id,
                            stat.bands))
        self.logger.info('MeterConfigStats: %s', configs)    