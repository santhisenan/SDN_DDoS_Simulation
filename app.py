from operator import attrgetter

import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub

import numpy as np

class SimpleMonitor13(simple_switch_13.SimpleSwitch13):

    def __init__(self, *args, **kwargs):
        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.state = {}
        self.unrolled_state = [0]*45
        self.topo_data = {'no_switch': 3, 'no_of_ports_per_switch': 3}
        self.init_thread = hub.spawn(self._monitor)
            
    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
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
        hub.sleep(10)
        while True:   
            self.get_state()
            hub.sleep(3)
            self.preprocess_state()

    def get_state(self):
        for dp in self.datapaths.values():
                self._request_stats(dp)

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        temp=[]
        body = ev.msg.body
        ofproto = ev.msg.datapath.ofproto
        parser = ev.msg.datapath.ofproto_parser

        pstat={}
        self.state[ev.msg.datapath.id].append(pstat)
        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match['in_port'],
                                             flow.match['eth_dst'])):
            if len(self.state[ev.msg.datapath.id]) == 1:
                self.state[ev.msg.datapath.id].append(stat.packet_count)
                self.state[ev.msg.datapath.id].append(stat.byte_count)
                self.state[ev.msg.datapath.id].append(stat.duration_nsec)
            else:
                self.state[ev.msg.datapath.id][1] = stat.packet_count
                self.state[ev.msg.datapath.id][2] = stat.byte_count
                self.state[ev.msg.datapath.id][3] = stat.duration_nsec

            req = parser.OFPPortStatsRequest(ev.msg.datapath, 0,stat.instructions[0].actions[0].port )
            ev.msg.datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body
        temp=[]
        
        for stat in body:
            temp.append(str(stat.rx_packets))
            temp.append(str(stat.rx_bytes))
            temp.append(str(stat.tx_packets))
            temp.append(str(stat.tx_bytes))
            self.state[ev.msg.datapath.id][0][stat.port_no]=temp


    def preprocess_state(self):
        next_unrolled_state = []
        for key in self.state:
            switch_data = self.state[key]

            port_data, packet_count, byte_count, duration_nsec = switch_data[0], switch_data[1], switch_data[2], switch_data[3]
            
            for port in range(1, 1+self.topo_data['no_of_ports_per_switch']):
                if port in port_data:
                    for val in port_data[port]:
                        next_unrolled_state.append(val) 
                else :
                    for i in range(0,4):
                        next_unrolled_state.append(0) 
            next_unrolled_state.append(packet_count)
            next_unrolled_state.append(byte_count)
            next_unrolled_state.append(duration_nsec)

        
        # next_unrolled_state_int =     
        # print(next_unrolled_state)
        next_unrolled_state= list(map(int, next_unrolled_state))
        temp=next_unrolled_state
        for i in range (0,45):
            next_unrolled_state[i]=next_unrolled_state[i]-self.unrolled_state[i]
        self.unrolled_state=temp
        print(next_unrolled_state)





