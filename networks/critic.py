from keras.layers import Dense, Input, merge
from keras.models import Model
from keras.optimizers import Adam
import keras.backend as keras_backend
import tensorflow


class CriticNetwork(object):
    def __init__(self, tensorflow_session, state_size, action_size,
                 hidden_units=(300, 600), learning_rate=0.0001, batch_size=64,
                 tau=0.001):
        """
        Constructor for the Actor network

        :param tensorflow_session: The tensorflow session.
            See https://www.tensorflow.org for more information on tensorflow
            sessions.
        :param state_size: An integer denoting the dimensionality of the states
            in the current problem
        :param action_size: An integer denoting the dimensionality of the
            actions in the current problem
        :param hidden_units: An iterable defining the number of hidden units in
            each layer. Soon to be depreciated. default: (300, 600)
        :param learning_rate: A fload denoting the speed at which the network
            will learn. default: 0.0001
        :param batch_size: An integer denoting the batch size. default: 64
        :param tau: A flot denoting the rate at which the target model will
            track the main model. Formally, the tracking function is defined as:

              target_weights = tau * main_weights + (1 - tau) * target_weights

            for more explanation on how and why this happens,
            please refer to the DDPG paper:

            Lillicrap, Hunt, Pritzel, Heess, Erez, Tassa, Silver, & Wiestra.
            Continuous Control with Deep Reinforcement Learning. arXiv preprint
            arXiv:1509.02971, 2015.

            default: 0.001
        """
        # Store parameters
        self._tensorflow_session = tensorflow_session
        self._batch_size = batch_size
        self._tau = tau
        self._learning_rate = learning_rate
        self._hidden = hidden_units

        # Let tensorflow and keras work together
        keras_backend.set_session(tensorflow_session)

        # Generate the main model
        self._model, self._state_input, self._action_input = \
            self._generate_model()
        # Generate carbon copy of the model so that we avoid divergence
        self._target_model, self._target_weights, self._target_state = \
            self._generate_model()
        # gradients for policy update
        self._action_gradients = tensorflow.gradients(self._model.output,
                                                      self._action_input)
        self._tensorflow_session.run(tensorflow.initialize_all_variables())

    def get_gradients(self, states, actions):
        """
        Returns the gradients.
        :param states:
        :param actions:
        :return:
        """
        return self._tensorflow_session.run(self._action_gradients, feed_dict={
            self._state_inputs: states,
            self._action_input: actions
        })[0]

    def train_target_model(self):
        """
        Updates the weights of the target network to slowly track the main
        network.

        The speed at which the target network tracks the main network is
        defined by tau, given in the constructor to this class. Formally,
        the tracking function is defined as:

            target_weights = tau * main_weights + (1 - tau) * target_weights

        :return: None
        """
        main_weights = self._model.get_weights()
        target_weights = self._target_model.get_weights()
        target_weights = [self._tau * main_weight + (1 - self._tau) *
                          target_weight for main_weight, target_weight in
                          zip(actor_weights, actor_target_weights)]
        self._target_model.set_weights(target_weights)

    def _generate_model(self):
        """
        Generates the model based on the hyperparameters defined in the
        constructor.

        :return: at tuple containing references to the model, state input layer,
            and action input later
        """
        state_input_layer = Input(shape=[self._state_size])
        action_input_layer = Input(shape=[self._action_size])
        s_layer = Dense(self._hidden[0], activation='relu')(state_input_layer)
        a_layer = Dense(self._hidden[0], activation='linear')(action_input_layer)
        hidden = Dense(self._hidden[1], activation='linear')(s_layer)
        hidden = merge([hidden, a_layer], mode='sum')
        hidden = Dense(self._hidden[1], activation='relu')(hidden)
        output_layer = Dense(1, activation='linear')(hidden)
        model = Model(input=[state_input_layer, action_input_layer],
                      output=output_layer)
        model.compile(loss='mse', optimizer=Adam(lr=self._learning_rate))
        return model, state_input_layer, action_input_layer
