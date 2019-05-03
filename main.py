import numpy as np
import tensorflow as tf
import sys
import os
import random
from collections import deque
import time

from operator import attrgetter
import simple_switch_13

from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.lib.ip import ipv4_to_bin, ipv4_to_str
from ryu.lib import packet
from ryu.lib.mac import haddr_to_bin

sys.path.insert(0, './ddpg')

from actor_network import ActorNetwork as Actor 
from critic_network import CriticNetwork as Critic 
from replay_buffer import ReplayBuffer as Memory


GAMMA = 0.99
HIDDEN_1_ACTOR = 8
HIDDEN_2_ACTOR = 8
HIDDEN_3_ACTOR = 8
HIDDEN_1_CRITIC = 8
HIDDEN_2_CRITIC = 8
HIDDEN_3_CRITIC = 8
LEARNING_RATE_ACTOR = 1e-3
LEARNING_RATE_CRITIC = 1e-3 #TODO
LR_DECAY = 1
L2_REG_ACTOR = 1e-6
L2_REG_CRITIC = 1e-6
DROPOUT_ACTOR = 0
DROPOUT_CRITIC = 0
NUM_EPISODES = 15000
MAX_STEPS_PER_EPISODE = 10000
TAU = 1e-2
TRAIN_EVERY = 1 #TODO add doc
REPLAY_MEM_CAPACITY = int(1e5)
MINI_BATCH_SIZE = 1024 #TODO
INITIAL_NOISE_SCALE = 0.1
NOISE_DECAY = 0.99
EXPLORATION_MU = 0.0
EXPLORATION_THETA = 0.15
EXPLORATION_SIGMA = 0.2
STATE_DIM = 120 #TODO
ACTION_DIM = 8 #TODO
NUMBER_OF_PORTS_PER_SWITCH = 3 #TODO
NUMBER_OF_SWITCHES = 8 #TODO
MAX_BANDWIDTH = 10000 #TODO
MIN_BANDWIDTH = 0.1 * MAX_BANDWIDTH
LAMBD = 0.9


class TrafficMonitor(simple_switch_13.SimpleSwitch13):

        def __init__(self, *args, **kwargs):
                super(TrafficMonitor, self).__init__(*args, **kwargs)
                self.init_thread = hub.spawn(self._monitor)
                self.network_info = {"no_of_ports_per_switch":NUMBER_OF_PORTS_PER_SWITCH,\
                        "no_of_switches":NUMBER_OF_SWITCHES}

                self.datapaths = {}
                self.state = {}
                self.unrolled_state = []
                self.input_state = []
                
                self.meter_bands = {}
                self.attack_count = 0
                self.benign_count = 0
                self.total_attack_count = 0
                self.total_benign_count = 0
                self.reward = 0.0

        # The event handler assiciated with this decorator is called on change of state in the network
        # i.e for eg: whenever a new switch is associated with the controller
        @set_ev_cls(ofp_event.EventOFPStateChange,[MAIN_DISPATCHER, DEAD_DISPATCHER])
        def _state_change_handler(self, ev):
                datapath = ev.datapath
                if ev.state == MAIN_DISPATCHER:
                        if datapath.id not in self.datapaths:
                                self.state[datapath.id]=[]
                                self.datapaths[datapath.id] = datapath
                                self.meter_bands[datapath.id] = MAX_BANDWIDTH
                elif ev.state == DEAD_DISPATCHER:
                        if datapath.id in self.datapaths:
                                del self.datapaths[datapath.id]
                                del self.meter_bands[datapath.id]

        def _monitor(self):
                print("Initializing...")
                hub.sleep(10)
                while True:
                        self.main()

    
