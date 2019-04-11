import tensorflow as tf


class CriticNetwork(tf.keras.Model):
    def __init__(self, state_dim, action_dim, h1_critic, h2_critic, h3_critic,
                 trainable):
        super(CriticNetwork, self).__init__(name='critic_network')
        self.state_dim = state_dim
        self.action_dim = action_dim
        self.h1_critic = h1_critic
        self.h2_critic = h2_critic
        self.h3_critic = h3_critic

        # The layers of the model
        self.hidden_1 = tf.layers.Dense(units=h1_critic, activation=tf.nn.relu,
                                        trainable=trainable,
                                        name='hidden_1')
        self.hidden_2 = tf.layers.Dense(units=h2_critic, activation=tf.nn.relu,
                                        trainable=trainable,
                                        name='hidden_2')
        self.hidden_3 = tf.layers.Dense(units=h3_critic, activation=tf.nn.relu,
                                        trainable=trainable,
                                        name='hidden_3')
        self.output_layer = tf.layers.Dense(units=1,
                                            trainable=trainable,
                                            name='output_layer')  # Default
        # activation function

    def call(self, input_state, input_action):
        inputs = tf.concat([input_state, input_action], axis=1)
        x = self.hidden_1(inputs)
        x = self.hidden_2(x)
        x = self.hidden_3(x)
        return self.output_layer(x)
