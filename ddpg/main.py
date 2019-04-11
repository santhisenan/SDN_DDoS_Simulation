import numpy as np
import gym
from gym import wrappers
import tensorflow as tf
import json
import sys
import os
from os import path
import random
from collections import deque


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
## Setup


writer = tf.summary.FileWriter("./tensorboard")

GAMMA = 0.99
ENV_NAME = 'Pendulum-v0'
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
STATE_DIM = 3 
ACTION_DIM = 1
OUTPUT_DIR = "output"

def main():
	env = gym.make(ENV_NAME)
	# set seeds to 0
	env.seed(0)
	np.random.seed(0)

	# prepare monitorings
	outdir = 'output'
	env = wrappers.Monitor(env, outdir, force=True)


	def writefile(fname, s):
		with open(path.join(outdir, fname), 'w') as fh:
			fh.write(s)


	

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
		actions = env.action_space.low + tf.nn.sigmoid(actions_unscaled)*(
			env.action_space.high - env.action_space.low)

	# slow target actor network
	with tf.variable_scope('target_actor', reuse=False):
		target_actor = Actor(STATE_DIM, ACTION_DIM, HIDDEN_1_ACTOR,
						HIDDEN_2_ACTOR, HIDDEN_3_ACTOR, trainable=True)
		# Slow target policy's outputted action for each next_state_ph (for training the critic)
		# use stop_gradient to treat the output values as constant targets when doing backprop
		target_next_actions_unscaled = target_actor.call(next_state_placeholder)
		target_next_actions_1 = env.action_space.low + tf.nn.sigmoid(target_next_actions_unscaled)*(
			env.action_space.high - env.action_space.low)
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
	writer.add_graph(sess.graph)

	#####################################################################################################
	## Training

	num_steps= 0
	for episode in range(NUM_EPISODES):

		total_reward = 0
		num_steps_in_episode = 0

		# Create noise
		noise = np.zeros(ACTION_DIM)
		noise_scale = (INITIAL_NOISE_SCALE * NOISE_DECAY ** episode) * \
			(env.action_space.high - env.action_space.low) #TODO: uses env
		
		# Initial state
		state = env.reset() #TODO: uses env

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
			next_state, reward, done, _info = env.step(action)
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

	

	# Finalize and upload results
	writefile('info.json', json.dumps(info))
	env.close()
	gym.upload(outdir)

main()