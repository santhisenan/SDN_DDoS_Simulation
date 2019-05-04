from operator import attrgetter
import simple_switch_13
import time

from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.lib.ip import ipv4_to_bin, ipv4_to_str
from ryu.lib import packet
from ryu.lib.mac import haddr_to_bin


NUMBER_OF_PORTS_PER_SWITCH = 3  # TODO
NUMBER_OF_SWITCHES  = 1  # TODO
MAX_BANDWIDTH = 10000  # TODO
MIN_BANDWIDTH = 0.1 * MAX_BANDWIDTH
LAMBD = 0.9
SPOOFED_SRC_IP = '10.1.1.1'
DEST_IP = '10.0.0.' + str(NUMBER_OF_SWITCHES + 1)

class TrafficMonitor(simple_switch_13.SimpleSwitch13):
    
    def __init__(self, *args, **kwargs):
        super(TrafficMonitor, self).__init__(*args, **kwargs)
        self.init_thread = hub.spawn(self._monitor)
        self.network_info = {"no_of_ports_per_switch":NUMBER_OF_PORTS_PER_SWITCH,
                             "no_of_switches":NUMBER_OF_SWITCHES}
        self.datapaths = {}
        self.meter_bands = {}
        # self.main()

    @set_ev_cls(ofp_event.EventOFPStateChange, \
    [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath

        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                    self.datapaths[datapath.id] = datapath
                    self.meter_bands[datapath.id] = MAX_BANDWIDTH

        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                    del self.datapaths[datapath.id]
                    del self.meter_bands[datapath.id]
    
    def _monitor(self):
        print("Initializing...")
        hub.sleep(10)
        # while True:
        self.main()

    def main(self):
        for dp in self.datapaths.values():
            rate = 100
            self.add_meter_band(dp, rate)
        time.sleep(10)

        for dp in self.datapaths.values():
            # pass
            self.send_meter_config_stats_request(dp)
        time.sleep(5)

        while True:
            for dp in self.datapaths.values():
                self.send_flow_stats_request(dp)
            time.sleep(10)

    def add_meter_band(self, datapath, rate):
        # datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        bands = []
        dropband = parser.OFPMeterBandDrop(rate=int(rate), burst_size=100)
        bands.append(dropband)

        # Delete meter incase it already exists (other instructions pre 
        # installed will still work)
        request = parser.OFPMeterMod(datapath=datapath, 
                                     command=ofproto.OFPMC_DELETE, 
                                     flags=ofproto.OFPMF_KBPS, 
                                     meter_id=1, bands=bands)
        datapath.send_msg(request)
        # Create meter
        request = parser.OFPMeterMod(datapath=datapath, 
                                     command=ofproto.OFPMC_ADD, 
                                     flags=ofproto.OFPMF_PKTPS, 
                                     meter_id=1, bands=bands)
        datapath.send_msg(request)


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


    def send_meter_stats_request(self, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        req = ofp_parser.OFPMeterStatsRequest(datapath, 0, ofp.OFPM_ALL)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPMeterStatsReply, MAIN_DISPATCHER)
    def meter_stats_reply_handler(self, ev):
        meters = []
        for stat in ev.msg.body:
            meters.append('meter_id=0x%08x len=%d flow_count=%d '
                        'packet_in_count=%d byte_in_count=%d '
                        'duration_sec=%d duration_nsec=%d '
                        'band_stats=%s' %
                        (stat.meter_id, stat.len, stat.flow_count,
                        stat.packet_in_count, stat.byte_in_count,
                        stat.duration_sec, stat.duration_nsec,
                        stat.band_stats))
        self.logger.info('MeterStats: %s', meters)

    def send_flow_stats_request(self, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        cookie = cookie_mask = 0
        match = ofp_parser.OFPMatch(in_port=1)
        req = ofp_parser.OFPFlowStatsRequest(datapath, 0,
                                            ofp.OFPTT_ALL,
                                            ofp.OFPP_ANY, ofp.OFPG_ANY,
                                            cookie, cookie_mask,
                                            match)
        # print(datapath.id)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        flows = []
        packet_count = 0
        # print(ev.msg.body)
        for stat in ev.msg.body:
            packet_count += stat.packet_count
            # flows.append('table_id=%s '
            #             'duration_sec=%d duration_nsec=%d '
            #             'priority=%d '
            #             'idle_timeout=%d hard_timeout=%d flags=0x%04x '
            #             'cookie=%d packet_count=%d byte_count=%d '
            #             'match=%s instructions=%s' %
            #             (stat.table_id,
            #             stat.duration_sec, stat.duration_nsec,
            #             stat.priority,
            #             stat.idle_timeout, stat.hard_timeout, stat.flags,
            #             stat.cookie, stat.packet_count, stat.byte_count,
            #             stat.match, stat.instructions))
        # self.logger.info('FlowStats: %s', flows)
        print(str(ev.msg.datapath.id) + ' ' + str(packet_count))