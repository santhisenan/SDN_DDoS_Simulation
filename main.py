import numpy as np
import tensorflow as tf
import sys
from os import path
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

#####################################################################################################
## Algorithm

# Deep Deterministic Policy Gradient (DDPG)
# An off-policy actor-critic algorithm that uses additive exploration noise (e.g. an Ornstein-Uhlenbeck process) on top
# of a deterministic policy to generate experiences (s, a, r, s'). It uses minibatches of these experiences from replay
# memory to update the actor (policy) and critic (Q function) parameters.
# Neural networks are used for function approximation.
# Slowly-changing "target" networks are used to improve stability and encourage convergence.
# Parameter updates are made via Adam.
# Assumes continuous action spaces!

#####################################################################################################



GAMMA = 0.99
HIDDEN_1_ACTOR = 8
HIDDEN_2_ACTOR = 8
HIDDEN_3_ACTOR = 8
HIDDEN_1_CRITIC = 8
HIDDEN_2_CRITIC = 8
HIDDEN_3_CRITIC = 8
LEARNING_RATE_ACTOR = 1e-3
LEARNING_RATE_CRITIC = 1e-3  # TODO
LR_DECAY = 1
L2_REG_ACTOR = 1e-6
L2_REG_CRITIC = 1e-6
DROPOUT_ACTOR = 0
DROPOUT_CRITIC = 0
NUM_EPISODES = 15000
MAX_STEPS_PER_EPISODE = 10000
TAU = 1e-2
TRAIN_EVERY = 1  # TODO add doc
REPLAY_MEM_CAPACITY = int(1e5)
MINI_BATCH_SIZE = 1024  # TODO
INITIAL_NOISE_SCALE = 0.1
NOISE_DECAY = 0.99
EXPLORATION_MU = 0.0
EXPLORATION_THETA = 0.15
EXPLORATION_SIGMA = 0.2
STATE_DIM = 105  # TODO
ACTION_DIM = 7  # TODO
NUMBER_OF_PORTS_PER_SWITCH = 3  # TODO
NUMBER_OF_SWITCHES  = 7  # TODO
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
        self.state = {}
        self.unrolled_state = []
        self.input_state = []

        self.meter_bands = {}
        self.attack_count = 0
        self.benign_count = 0
        self.total_attack_count = 0
        self.total_benign_count = 0
        self.reward = 0.0

    # The event handler assiciated with this decorator is called on change of 
    # state in the network
    # i.e for eg: whenever a new switch is associated with the controller

    @set_ev_cls(ofp_event.EventOFPStateChange, \
        [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                    self.state[datapath.id] = []
                    self.datapaths[datapath.id] = datapath
                    self.meter_bands[datapath.id] = MAX_BANDWIDTH
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                    del self.datapaths[datapath.id]
                    del self.meter_bands[datapath.id]

    def _monitor(self):
        print("Initializing...")
        hub.sleep(10)
        self.main()

    def get_state(self):
        # TODO: separate function
        # self.attack_count = 0
        # self.benign_count = 0
        # self.total_attack_count = 0
        # self.total_benign_count = 0
        for dp in self.datapaths.values():
            self.send_flow_stats_request(dp)
        hub.sleep(2) #TODO sleep
        self.format_state()  # TODO: Not sure where to call
        self.calculate_reward()

    def send_flow_stats_request(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        datapath = ev.msg.datapath
        ofp_parser = datapath.ofproto_parser
        
        packet_count_n = 0
        byte_count_n = 0
        flow_count_n = 0

        match = ofp_parser.OFPMatch(eth_type=0x0800, ipv4_src=SPOOFED_SRC_IP)

        for stat in ([flow for flow in body]):
            flow_count_n += 1
            packet_count_n += stat.packet_count
            byte_count_n += stat.byte_count
            print(str(stat))
                #                     

            try:
                if stat.match.__getitem__("ipv4_src") == SPOOFED_SRC_IP and \
                    stat.match.__getitem__("ipv4_dst") == DEST_IP and \
                        datapath.id in range(4, 7):
                    print("*")
                    self.total_attack_count += stat.packet_count
                elif stat.match.__getitem__("ipv4_src") != SPOOFED_SRC_IP and \
                        datapath.id in range(4, 7):
                    print("**")
                    self.total_benign_count += stat.packet_count
            except:
                # print("in Except")
                pass

            try:
                if stat.match.__getitem__("ipv4_src") == SPOOFED_SRC_IP and \
                    stat.match.__getitem__("ipv4_dst") == DEST_IP and \
                        datapath.id == 7:
                    self.attack_count += stat.packet_count
                elif stat.match.__getitem__("ipv4_dst") == DEST_IP and \
                        datapath.id == 7:
                    self.benign_count += stat.packet_count
            except:
                pass

        if len(self.state[datapath.id]) == 0:
            self.state[datapath.id].append({})
            self.state[datapath.id].append(packet_count_n)
            self.state[datapath.id].append(byte_count_n)
            self.state[datapath.id].append(flow_count_n)
        else:
            self.state[datapath.id][1] = packet_count_n
            self.state[datapath.id][2] = byte_count_n
            self.state[datapath.id][3] = flow_count_n

        for port_no in range(1, self.network_info["no_of_ports_per_switch"] + 1):
            req = ofp_parser.OFPPortStatsRequest(datapath, 0, port_no)
            datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body
        datapath = ev.msg.datapath
        temp = []

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
                port_data, packet_count, byte_count, flow_count = \
                    switch_data[0], switch_data[1], switch_data[2], \
                        switch_data[3]

                for port in range(1, 1 + \
                    self.network_info['no_of_ports_per_switch']):
                    if port in port_data:
                        for val in port_data[port]:
                            curr_unrolled_state.append(val)
                    else:
                        for i in range(0, 4):
                            curr_unrolled_state.append(0)

                curr_unrolled_state.append(packet_count)
                curr_unrolled_state.append(byte_count)
                curr_unrolled_state.append(flow_count)

        if(len(curr_unrolled_state) != 0):
            curr_unrolled_state = list(map(int, curr_unrolled_state))
            iter_count = self.network_info['no_of_switches'] * \
                (self.network_info['no_of_ports_per_switch'] * 4 + 3)

            if(len(self.unrolled_state) != 0):
                prev_state = self.unrolled_state
            else:
                prev_state = [0]*iter_count

            temp_unrolled_state = [0]*iter_count

            for i in range(iter_count):
                try:
                    temp_unrolled_state[i] = curr_unrolled_state[i] - \
                        prev_state[i]
                except:
                    self.logger.info("Out of index error would have occured!")

            self.input_state = temp_unrolled_state
            self.unrolled_state = curr_unrolled_state

    def calculate_reward(self):
        # print("attack on 7 " + str(self.attack_count))
        # print("benign on 7 " + str(self.benign_count))
        print("Attack " + str(self.total_attack_count))
        print("Benign " + str(self.total_benign_count))

        # pa = float(self.attack_count)/float(self.total_attack_count)
        # pb = float(self.benign_count)/float(self.total_benign_count)

        # self.reward = float(LAMBD*pb) + float((1 - LAMBD)*(1 - pa))
        # print(self.reward)

    def add_meter_band(self, datapath, rate):
        # datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        bands = []
        dropband = parser.OFPMeterBandDrop(rate=int(rate), burst_size=0)
        bands.append(dropband)

        # Delete meter incase it already exists (other instructions pre 
        # installed will still work)
        request = parser.OFPMeterMod(datapath=datapath, 
                                     command=ofproto.OFPMC_DELETE, 
                                     flags=ofproto.OFPMF_PKTPS, 
                                     meter_id=1, bands=bands)
        datapath.send_msg(request)
        #Create meter
        request = parser.OFPMeterMod(datapath=datapath, 
                                     command=ofproto.OFPMC_ADD, 
                                     flags=ofproto.OFPMF_PKTPS, 
                                     meter_id=1, bands=bands)
        datapath.send_msg(request)

    def reset(self):
        for i in range(1, NUMBER_OF_SWITCHES + 1):
            print(str(i))
            self.add_meter_band(self.datapaths[i], MAX_BANDWIDTH)
        self.get_state()

    def step(self, action):
        dpid = 1
        for bandwidth in action:
            self.add_meter_band(self.datapaths[dpid], bandwidth)
            dpid += 1
        
        self.get_state()
        time.sleep(2)

        next_state = self.input_state
        reward = self.reward
        done = False  # TODO

        self.attack_count = 0
        self.benign_count = 0
        self.total_attack_count = 0
        self.total_benign_count = 0

        return next_state, reward, done

    def main(self):
        np.random.seed(0)
        replay_memory = deque(maxlen=REPLAY_MEM_CAPACITY)

        def add_to_memory(experience):
            replay_memory.append(experience)

        def sample_from_memory(minibatch_size):
            return random.sample(replay_memory, minibatch_size)

        tf.reset_default_graph()

        # placeholders
        state_placeholder = tf.placeholder(
            dtype=tf.float32, shape=[None, STATE_DIM])
        action_placeholder = tf.placeholder(
            dtype=tf.float32, shape=[None, ACTION_DIM])
        reward_placeholder = tf.placeholder(dtype=tf.float32, shape=[None])
        next_state_placeholder = tf.placeholder(
            dtype=tf.float32, shape=[None, STATE_DIM])
        # indicators (go into target computation)
        is_not_terminal_placeholder = tf.placeholder(
            dtype=tf.float32, shape=[None])
        is_training_placeholder = tf.placeholder(
            dtype=tf.bool, shape=())  # for dropout

        # episode counter
        episodes = tf.Variable(0.0, trainable=False, name='episodes')
        episode_incr_op = episodes.assign_add(1)

        # actor network
        with tf.variable_scope('actor'):
            actor = Actor(STATE_DIM, ACTION_DIM, HIDDEN_1_ACTOR,
                          HIDDEN_2_ACTOR, HIDDEN_3_ACTOR, trainable=True)
            # Policy's outputted action for each state_ph (for generating 
            # actions and training the critic)
            # actions = generate_actor_network(state_ph, trainable=True, reuse=False)
            actions_unscaled = actor.call(state_placeholder)
            actions = MIN_BANDWIDTH + tf.nn.sigmoid(actions_unscaled)*(
                MAX_BANDWIDTH - MIN_BANDWIDTH)

        # slow target actor network
        with tf.variable_scope('target_actor', reuse=False):
            target_actor = Actor(STATE_DIM, ACTION_DIM, HIDDEN_1_ACTOR,
                                 HIDDEN_2_ACTOR, HIDDEN_3_ACTOR, trainable=True)
            # Slow target policy's outputted action for each next_state_ph 
            # (for training the critic)
            # use stop_gradient to treat the output values as constant targets 
            # when doing backprop
            target_next_actions_unscaled = target_actor.call(
                next_state_placeholder)
            target_next_actions_1 = MIN_BANDWIDTH + tf.nn.sigmoid(target_next_actions_unscaled)*(
                MAX_BANDWIDTH - MIN_BANDWIDTH)
            target_next_actions = tf.stop_gradient(target_next_actions_1)

        with tf.variable_scope('critic') as scope:
            critic = Critic(STATE_DIM, ACTION_DIM, HIDDEN_1_CRITIC,
                            HIDDEN_2_CRITIC, HIDDEN_3_CRITIC, trainable=True)
            # Critic applied to state_ph and a given action (for training critic)
            q_values_of_given_actions = critic.call(
                state_placeholder, action_placeholder)
            # Critic applied to state_ph and the current policy's outputted actions for state_ph (for training actor via deterministic policy gradient)
            q_values_of_suggested_actions = critic.call(
                state_placeholder, actions)

        # slow target critic network
        with tf.variable_scope('target_critic', reuse=False):
            target_critic = Critic(STATE_DIM, ACTION_DIM, HIDDEN_1_CRITIC,
                                   HIDDEN_2_CRITIC, HIDDEN_3_CRITIC, trainable=True)
            # Slow target critic applied to slow target actor's outputted actions for next_state_ph (for training critic)
            q_values_next = tf.stop_gradient(target_critic.call(
                next_state_placeholder, target_next_actions))

        # isolate vars for each network
        actor_vars = tf.get_collection(
            tf.GraphKeys.TRAINABLE_VARIABLES, scope='actor')
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

        num_steps = 0
        for episode in range(NUM_EPISODES):
            total_reward = 0
            num_steps_in_episode = 0

            # Create noise
            noise = np.zeros(ACTION_DIM)
            noise_scale = (INITIAL_NOISE_SCALE * NOISE_DECAY ** episode) * \
                (MAX_BANDWIDTH - MIN_BANDWIDTH)  # TODO: uses env

            # Initial state
            self.reset()  # TODO: uses env
            state = self.input_state

            for t in range(MAX_STEPS_PER_EPISODE):
                # choose action based on deterministic policy
                state = np.asarray(state)
                state = state.reshape(1, state.shape[0])
                action, = sess.run(actions,
                                   feed_dict={state_placeholder: state, is_training_placeholder: False})

                # add temporally-correlated exploration noise to action 
                # (using an Ornstein-Uhlenbeck process)
                noise = EXPLORATION_THETA * \
                    (EXPLORATION_MU - noise) + \
                    EXPLORATION_SIGMA*np.random.randn(ACTION_DIM)
                action += noise_scale*noise

                # take step
                next_state, reward, done, = self.step(action)
                total_reward += reward

                add_to_memory((state, action, reward, next_state,
                               # is next_observation a terminal state?
                               # 0.0 if done and not env.env._past_limit() else 1.0))
                               0.0 if done else 1.0))
                # update network weights to fit a minibatch of experience
                if num_steps % TRAIN_EVERY == 0 and len(replay_memory) >= MINI_BATCH_SIZE:

                    minibatch = sample_from_memory(MINI_BATCH_SIZE)


                    # update the critic and actor params using mean-square value 
                    # error and deterministic policy gradient, respectively
                    _, _ = sess.run([critic_train_op, actor_train_op],
                                    feed_dict={
                        state_placeholder: np.asarray([elem[0] for elem in minibatch]),
                        action_placeholder: np.asarray([elem[1] for elem in minibatch]),
                        reward_placeholder: np.asarray([elem[2] for elem in minibatch]),
                        next_state_placeholder: np.asarray([elem[3] for elem in minibatch]),
                        is_not_terminal_placeholder: np.asarray([elem[4] for elem in minibatch]),

                        is_training_placeholder: True})

                    # update slow actor and critic targets towards current actor and critic
                    _ = sess.run(update_targets_op)

                state = next_state
                num_steps += 1
                num_steps_in_episode += 1

                if done:
                    # Increment episode counter
                    _ = sess.run(episode_incr_op)
                    break

            print('Episode %2i, Reward: %7.3f, Steps: %i, Final noise scale: %7.3f' % (
                episode, total_reward, num_steps_in_episode, noise_scale))
