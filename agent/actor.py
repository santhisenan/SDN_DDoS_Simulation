import tensorflow as tf
from tensorflow import keras
from keras.models import Sequential
from keras.layers import Dense, Input
from keras.optimizers import Adam

tf.enable_eager_execution()

class Actor():

    def __init__(self, tf_session, state_size, action_size, \
                 hidden_units = (300, 600), learning_rate = 0.0001, \
                 batch_size = 64, tau = 0.001):
        self._tf_session = tf_session
        self._state_size = state_size
        self._action_size = action_size
        self._hidden_units = hidden_units
        self._learning_rate = learning_rate
        self._batch_size = batch_size
        self._tau = tau

        self._model, self._model_weights, self._model_input = \
            self._generate_model()
        self._target_model, self._target_model_weights, \
            self._target_model_input = self._generate_model()
        
        self._action_grads = tf.placeholder(tf.float32, shape=self._action_size)
        self._parameter_grads = tf.gradients(self._model.output, \
            self._model_weights, -self._action_grads)

        self._grads = zip(self._parameter_grads, self._model_weights)

        self._optimize = tf.train.AdamOptimizer(self._learning_rate) \
            .apply_gradients(self._grads)
        
        self._tf_session.run(tf.initialize_all_variables())
        # keras_backend.set_session(tensorflow_session)

    
    def _generate_model(self):
        input_layer = Input(shape=[self._state_size])
        hidden_layer_1 = Dense(self._hidden[0], activation='relu')(input_layer)
        hidden_layer_2 = Dense(self._hidden_units[2], \ 
                               activation='relu')(hidden_layer_1)
        output_layer = Dense(self._action_size, \
                             activation=sigmoid)(hidden_layer_2)
        model = Model(input=input_layer, output=output_layer)
        return model, model.trainable_weights, input_layer




