import numpy as np
import tensorflow as tf
import json
import sys
import os
from os import path
import random
from collections import deque

from operator import attrgetter
import simple_switch_13

from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.lib.ip import ipv4_to_bin, ipv4_to_str
from ryu.lib import packet
from ryu.lib.mac import haddr_to_bin

sys.path.insert(0, '/home/musthafa/project/SDN_DDoS_Simulation/ddpg')

from actor_network import ActorNetwork as Actor 
from critic_network import CriticNetwork as Critic 
from replay_buffer import ReplayBuffer as Memory

#TODO : reset() , step() , 

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
STATE_DIM = 45
ACTION_DIM = 3
OUTPUT_DIR = "output"
MAX_BANDWIDTH = 10000
MIN_BANDWIDTH = 0.1 * MAX_BANDWIDTH


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

        self.meter_bands = {}

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
                self.meter_bands[datapath.id] = 10000
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]
                del self.packet_count[datapath.id]
                del self.attack_packet_count[datapath.id]
                del self.meter_bands[datapath.id]

    def _monitor(self):
        print("Initializing...")
        hub.sleep(10)
        while True:
            self.main()

            # self.add_meter(self.datapaths[3])

    def get_state(self):
        self.find_state()
        hub.sleep(2)
        self.update_attack_packet_count(self.datapaths[3])
        hub.sleep(2)
        self.format_state()

    # Request statistics associated with each switch (dp)
    def find_state(self):
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
            # print(str(stat))
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
            # self.add_meter_band(datapath, 10000)

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
            # self.get_reward(self.datapaths[3])

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

    def get_reward(self):
        # self.send_meter_stats_request(datapath)
        packets_in_network = sum(self.packet_count.values())
        attack_packets_in_network = sum(self.attack_packet_count.values())
        try:
            # pass
            print("Reward = " + str(self.attack_packet_count[3]) + " " + str(self.packet_count[3]))
        except:
            print("Some error while calculating reward!")

    def add_meter_band(self, datapath, rate):
        # datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        bands = []
        dropband = parser.OFPMeterBandDrop(rate=int(rate), burst_size=0)
        bands.append(dropband)

        #Delete meter incase it already exists (other instructions pre installed will still work)
        request = parser.OFPMeterMod(datapath=datapath,command=ofproto.OFPMC_DELETE,flags=ofproto.OFPMF_PKTPS,meter_id=1,bands=bands)
        datapath.send_msg(request)
        #Create meter
        request = parser.OFPMeterMod(datapath=datapath,command=ofproto.OFPMC_ADD, flags=ofproto.OFPMF_PKTPS,meter_id=1,bands=bands)
        datapath.send_msg(request)

        self.logger.send_meter_config_stats_request(datapath)

    # def train(self):
    #     state=self.get_state()
    #     hub.sleep(3)
    #     action = bin(self.agent.act(state))[2:].zfill(3)

    #     dpid = 0
    #     for i in action:
    #         dpid += 1
    #         if(i == '1'):
    #             if(self.meter_bands[dpid] <= 1000):
    #                 pass
    #             else :
    #                 rate_new = self.meter_bands[dpid] - 1000
    #                 self.meter_bands[dpid] = rate_new
    #                 self.add_meter_band(self.datapaths[dpid], rate_new)
    #                 self.send_meter_config_stats_request(self.datapaths[dpid])

    #     self.get_reward()   

    #     next_state=self.get_state()
    #     rew= self.get_reward()
    #     agent.memory.append((state, action, reward, next_state, done))


    #ENV Functions starts
    def reset(self):
        self.add_meter_band(1,MAX_BANDWIDTH)
        self.add_meter_band(2,MAX_BANDWIDTH)
        self.add_meter_band(3,MAX_BANDWIDTH)
        self.get_state()
        
    

    def step(self,action):
        # To return next_state, reward, done, _info

        



    def main(self):
        
        np.random.seed(0)
        # np.set_printoptions(threshold=np.nan)

        # used for O(1) popleft() operation
        replay_memory = deque(maxlen=REPLAY_MEM_CAPACITY)
        def add_to_memory(experience):
            replay_memory.append(experience)

        def sample_from_memory(minibatch_size):
            return random.sample(replay_memory, minibatch_size)






        #####################################################################################################
        ## Tensorflow


        tf.reset_default_graph()

        # placeholders
        state_placeholder = tf.placeholder(dtype=tf.float32, shape=[None, STATE_DIM])
        action_placeholder = tf.placeholder(dtype=tf.float32, shape=[None, ACTION_DIM])
        reward_placeholder = tf.placeholder(dtype=tf.float32, shape=[None])
        next_state_placeholder = tf.placeholder(dtype=tf.float32, shape=[None, STATE_DIM])
        # indicators (go into target computation)
        is_not_terminal_placeholder = tf.placeholder(dtype=tf.float32, shape=[None])
        is_training_placeholder = tf.placeholder(dtype=tf.bool, shape=())  # for dropout

        # episode counter
        episodes = tf.Variable(0.0, trainable=False, name='episodes')
        episode_incr_op = episodes.assign_add(1)

        # actor network
        with tf.variable_scope('actor'):
            actor = Actor(STATE_DIM, ACTION_DIM, HIDDEN_1_ACTOR,
                HIDDEN_2_ACTOR, HIDDEN_3_ACTOR, trainable=True)
            # Policy's outputted action for each state_ph (for generating actions and training the critic)
            # actions = generate_actor_network(state_ph, trainable=True, reuse=False)
            actions_unscaled = actor.call(state_placeholder)
            actions = MIN_BANDWIDTH + tf.nn.sigmoid(actions_unscaled)*(
                MAX_BANDWIDTH - MIN_BANDWIDTH)

        # slow target actor network
        with tf.variable_scope('target_actor', reuse=False):
            target_actor = Actor(STATE_DIM, ACTION_DIM, HIDDEN_1_ACTOR,
                            HIDDEN_2_ACTOR, HIDDEN_3_ACTOR, trainable=True)
            # Slow target policy's outputted action for each next_state_ph (for training the critic)
            # use stop_gradient to treat the output values as constant targets when doing backprop
            target_next_actions_unscaled = target_actor.call(next_state_placeholder)
            target_next_actions_1 = MIN_BANDWIDTH + tf.nn.sigmoid(target_next_actions_unscaled)*(
                MAX_BANDWIDTH - MIN_BANDWIDTH)
            target_next_actions = tf.stop_gradient(target_next_actions_1)


        with tf.variable_scope('critic') as scope:
            critic = Critic(STATE_DIM, ACTION_DIM, HIDDEN_1_CRITIC,
                            HIDDEN_2_CRITIC, HIDDEN_3_CRITIC, trainable=True)
            # Critic applied to state_ph and a given action (for training critic)
            q_values_of_given_actions = critic.call(state_placeholder, action_placeholder)
            # Critic applied to state_ph and the current policy's outputted actions for state_ph (for training actor via deterministic policy gradient)
            q_values_of_suggested_actions = critic.call(state_placeholder, actions)

        # slow target critic network
        with tf.variable_scope('target_critic', reuse=False):
            target_critic = Critic(STATE_DIM, ACTION_DIM, HIDDEN_1_CRITIC,
                                HIDDEN_2_CRITIC, HIDDEN_3_CRITIC, trainable=True)
            # Slow target critic applied to slow target actor's outputted actions for next_state_ph (for training critic)
            q_values_next = tf.stop_gradient(target_critic.call(next_state_placeholder, target_next_actions))

        # isolate vars for each network
        actor_vars = tf.get_collection(tf.GraphKeys.TRAINABLE_VARIABLES, scope='actor')
        target_actor_vars = tf.get_collection(
            tf.GraphKeys.GLOBAL_VARIABLES, scope='target_actor')
        critic_vars = tf.get_collection(
            tf.GraphKeys.TRAINABLE_VARIABLES, scope='critic')
        target_critic_vars = tf.get_collection(
            tf.GraphKeys.GLOBAL_VARIABLES, scope='target_critic')

        # update values for slowly-changing targets towards current actor and critic
        update_target_ops = []
        for i, target_actor_var in enumerate(target_actor_vars):
            update_target_actor_op = target_actor_var.assign(
                TAU*actor_vars[i]+(1-TAU)*target_actor_var)
            update_target_ops.append(update_target_actor_op)

        for i, target_var in enumerate(target_critic_vars):
            target_critic_op = target_var.assign(
                TAU*critic_vars[i]+(1-TAU)*target_var)
            update_target_ops.append(target_critic_op)

        update_targets_op = tf.group(
            *update_target_ops, name='update_slow_targets')

        # One step TD targets y_i for (s,a) from experience replay
        # = r_i + gamma*Q_slow(s',mu_slow(s')) if s' is not terminal
        # = r_i if s' terminal
        targets = tf.expand_dims(
            reward_placeholder, 1) + tf.expand_dims(is_not_terminal_placeholder, 1) * GAMMA * q_values_next

        # 1-step temporal difference errors
        td_errors = targets - q_values_of_given_actions

        # critic loss function (mean-square value error with regularization)
        critic_loss = tf.reduce_mean(tf.square(td_errors))
        for var in critic_vars:
            if not 'bias' in var.name:
                critic_loss += L2_REG_CRITIC * 0.5 * tf.nn.l2_loss(var)

        # critic optimizer
        critic_train_op = tf.train.AdamOptimizer(
            LEARNING_RATE_CRITIC*LR_DECAY**episodes).minimize(critic_loss)

        # actor loss function (mean Q-values under current policy with regularization)
        actor_loss = -1*tf.reduce_mean(q_values_of_suggested_actions)
        for var in actor_vars:
            if not 'bias' in var.name:
                actor_loss += L2_REG_ACTOR * 0.5 * tf.nn.l2_loss(var)

        # actor optimizer
        # the gradient of the mean Q-values wrt actor params is the deterministic policy gradient (keeping critic params fixed)
        actor_train_op = tf.train.AdamOptimizer(
            LEARNING_RATE_ACTOR*LR_DECAY**episodes).minimize(actor_loss, var_list=actor_vars)

        # initialize session
        sess = tf.Session()
        sess.run(tf.global_variables_initializer())
        # print(sess.run(tf.report_uninitialized_variables()))
        

        #####################################################################################################
        ## Training

        num_steps= 0
        for episode in range(NUM_EPISODES):

            total_reward = 0
            num_steps_in_episode = 0

            # Create noise
            noise = np.zeros(ACTION_DIM)
            noise_scale = (INITIAL_NOISE_SCALE * NOISE_DECAY ** episode) * \
                (MAX_BANDWIDTH - MIN_BANDWIDTH) #TODO: uses env
            
            # Initial state
            self.reset() #TODO: uses env
            state = self.input_state

            for t in range(MAX_STEPS_PER_EPISODE):
                # choose action based on deterministic policy
                # print(state.shape)
                action, = sess.run(actions, 
                    feed_dict = {state_placeholder: state[None], is_training_placeholder: False})

                # add temporally-correlated exploration noise to action (using an Ornstein-Uhlenbeck process)
                # print(action_for_state)
                noise = EXPLORATION_THETA*(EXPLORATION_MU - noise) + EXPLORATION_SIGMA*np.random.randn(ACTION_DIM)
                # print(noise_scale*noise_process)
                action += noise_scale*noise

                # take step
                next_state, reward, done, _info = self.step(action)
                total_reward += reward

                add_to_memory((state, action, reward, next_state, 
                # is next_observation a terminal state?
                # 0.0 if done and not env.env._past_limit() else 1.0))
                0.0 if done else 1.0))
                # update network weights to fit a minibatch of experience
                if num_steps%TRAIN_EVERY == 0 and len(replay_memory) >= MINI_BATCH_SIZE:

                    # grab N (s,a,r,s') tuples from replay memory
                    # state_batch, action_batch, reward_batch, done_batch, \
                    #      next_state_batch = \
                    minibatch = sample_from_memory(MINI_BATCH_SIZE)
                    # print(minibatch[1][1])

                    # update the critic and actor params using mean-square value error and deterministic policy gradient, respectively
                    _, _ = sess.run([critic_train_op, actor_train_op], 
                        feed_dict = {
                            state_placeholder: np.asarray([elem[0] for elem in minibatch]),
                            action_placeholder: np.asarray([elem[1] for elem in minibatch]),
                            reward_placeholder: np.asarray([elem[2] for elem in minibatch]),
                            next_state_placeholder: np.asarray([elem[3] for elem in minibatch]),
                            is_not_terminal_placeholder: np.asarray([elem[4] for elem in minibatch]),
                            
                            is_training_placeholder: True})

                    # update slow actor and critic targets towards current actor and critic
                    _ = sess.run(update_targets_op)

                state = next_state
                print(next_state.shape)
                num_steps += 1
                num_steps_in_episode += 1
                
                if done: 
                    # Increment episode counter
                    _ = sess.run(episode_incr_op)
                    break
                
            print('Episode %2i, Reward: %7.3f, Steps: %i, Final noise scale: %7.3f'%(episode,total_reward,num_steps_in_episode, noise_scale))

	

	



    


