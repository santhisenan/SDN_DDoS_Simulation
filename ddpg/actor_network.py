import tensorflow as tf

class ActorNetwork(tf.keras.Model):
    def __init__(self, state_dim, action_dim, h1_actor, h2_actor, h3_actor,
                 trainable):
        super(ActorNetwork, self).__init__(name='actor_network')
        self.state_dim = state_dim
        self.action_dim = action_dim
        self.h1_actor = h1_actor
        self.h2_actor = h2_actor
        self.h3_actor = h3_actor

        # The layers of the model
        self.hidden_1 = tf.layers.Dense(units=h1_actor, activation=tf.nn.relu, 
                                        trainable=trainable, 
                                        name='hidden_1')
        self.hidden_2 = tf.layers.Dense(units=h2_actor, activation=tf.nn.relu,
                                        trainable=trainable,
                                        name='hidden_2')
        self.hidden_3 = tf.layers.Dense(units=h3_actor, activation=tf.nn.relu,
                                        trainable=trainable,
                                        name='hidden_3')
        self.output_layer = tf.layers.Dense(units=action_dim, 
                                            trainable=trainable,
                                            name='output_layer') 

    def call(self, inputs):
        x = self.hidden_1(inputs)
        x = self.hidden_2(x)
        x = self.hidden_3(x)
        return self.output_layer(x)

