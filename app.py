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
        self.get_state()
        hub.sleep(3)


    

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
        
#         self.logger.info('datapath         '
#                          'in-port  eth-dst           '
#                          'out-port packets  bytes')
#         self.logger.info('---------------- '
#                          '-------- ----------------- '
#                          '-------- -------- --------')
        pstat={}
        self.state[ev.msg.datapath.id].append(pstat)
        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match['in_port'],
                                             flow.match['eth_dst'])):
            # print("*")
            # temp.append(ev.msg.datapath.id)
            # temp.append(stat.match['in_port'])
            # temp.append(stat.match['eth_dst'])
            # print(ev.msg.datapath.id)
            if len(self.state[ev.msg.datapath.id]) == 1:
                # self.state[ev.msg.datapath.id].append(stat.instructions[0].actions[0].port)
                self.state[ev.msg.datapath.id].append(stat.packet_count)
                self.state[ev.msg.datapath.id].append(stat.byte_count)
                self.state[ev.msg.datapath.id].append(stat.duration_nsec)
            else:
                # self.state[ev.msg.datapath.id][0] = stat.instructions[0].actions[0].port
                self.state[ev.msg.datapath.id][1] = stat.packet_count
                self.state[ev.msg.datapath.id][2] = stat.byte_count
                self.state[ev.msg.datapath.id][3] = stat.duration_nsec
            # print("=====================================================================================================")
            # print("Port No="+str(stat.instructions[0].actions[0].port))
            # print("Packet Count="+str(stat.packet_count))
            # print("byte count="+str(stat.byte_count))
            # print("duration nsec="+str(stat.duration_nsec))
            
            req = parser.OFPPortStatsRequest(ev.msg.datapath, 0,stat.instructions[0].actions[0].port )
            ev.msg.datapath.send_msg(req)
            # print(self.state)
            
            
        
            #print(temp)
        

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body
        # self.logger.info('datapath         port     '
        #                  'rx-pkts  rx-bytes rx-error '
        #                  'tx-pkts  tx-bytes tx-error')
        # self.logger.info('---------------- -------- '
        #                  '-------- -------- -------- '
        # 
        #                  '-------- -------- --------')
        # 
        # print("*")
        temp=[]
        
        for stat in body:
            temp.append(str(stat.port_no))
            temp.append(str(stat.rx_packets))
            temp.append(str(stat.rx_bytes))
            temp.append(str(stat.tx_packets))
            temp.append(str(stat.tx_bytes))
            self.state[ev.msg.datapath.id][0][stat.port_no]=temp
        print(self.state)
            # print("rx_packets="+str(stat.rx_packets))
            # print("rx_bytes="+str(stat.rx_bytes))
            # print("tx_packets="+str(stat.tx_packets))
            # print("tx_bytes="+str(stat.tx_bytes))




