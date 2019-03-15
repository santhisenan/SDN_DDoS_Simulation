from agent import Agent

from operator import attrgetter
import simple_switch_13

from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
# from ryu.lib.packet import packet
# from ryu.lib.packet import ethernet
# from ryu.lib.packet import ipv4
# from ryu.lib.packet import ether_types

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

    # TODO:
    # get_state()
    # get_reward()
    # perform_action()


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
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        print("Initializing...")
        hub.sleep(10)
        while True:
            self.get_state()
            hub.sleep(3)

    # Request statistics associated with each switch (dp)
    def get_state(self):
        self.updated_port_count = 0

        for dp in self.datapaths.values():
            self.send_aggregate_stats_request(dp)

        # while(self.updated_port_count <= self.network_info["no_of_ports_per_switch"]*self.network_info["no_of_switches"]):
        #     print(self.updated_port_count)
        #     pass
        
        self.format_state()

    def send_aggregate_stats_request(self, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        cookie = cookie_mask = 0
        match = ofp_parser.OFPMatch()
        req = ofp_parser.OFPAggregateStatsRequest(datapath, 0,ofp.OFPTT_ALL,ofp.OFPP_ANY,ofp.OFPG_ANY,cookie, cookie_mask,match)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPAggregateStatsReply, MAIN_DISPATCHER)
    def aggregate_stats_reply_handler(self, ev):
        body = ev.msg.body
        datapath = ev.msg.datapath

        print(ev.msg)
        
        if len(self.state[datapath.id]):
            self.state[datapath.id][1] = body.packet_count
            self.state[datapath.id][2] = body.byte_count
            self.state[datapath.id][3] = body.flow_count
        else:
            self.state[datapath.id].append({})
            self.state[datapath.id].append(body.packet_count)
            self.state[datapath.id].append(body.byte_count)
            self.state[datapath.id].append(body.flow_count)

        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        for port_no in range(1, self.network_info["no_of_ports_per_switch"] + 1):
            req = ofp_parser.OFPPortStatsRequest(datapath, 0, port_no)
            datapath.send_msg(req)
            self.updated_port_count += 1

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

        if(len(curr_unrolled_state)):
            curr_unrolled_state = list(map(int, curr_unrolled_state))
            iter_count = self.network_info['no_of_switches']*(self.network_info['no_of_ports_per_switch'] * 4 + 3)

            if(len(self.unrolled_state)):
                prev_state = self.unrolled_state
            else:
                prev_state = [0]*iter_count
            
            temp_unrolled_state = [0]*iter_count

            for i in range(iter_count):
                temp_unrolled_state[i] = curr_unrolled_state[i] - prev_state[i]

            self.input_state = temp_unrolled_state
            self.unrolled_state = curr_unrolled_state
            # print(self.input_state)

    
    # def get_reward():
        

