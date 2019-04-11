from collections import deque
import random
import numpy as np 

class ReplayBuffer(object):
    
    def __init__(self, buffer_size):
        self._buffer_size = buffer_size
        self._count = 0
        self._buffer = deque()

    def insert(self, _experience):
        # _experience = (state, action, reward, done, next_state)
        if(self._count <= self._buffer_size):
            self._buffer.append(_experience)
            self._count += 1
        else:
            self._buffer.popleft()
            self._buffer.append(_experience)
    
    def size(self):
        return self._count
    
    def sample_batch(self, batch_size=32):
        '''
        If the number of elements in the replay memory is less than the required 
        batch_size, then return only those elements present in the memory, else
        return 'batch_size' number of elements.
        '''

        _available_batch_length = \
            self._count if self._count < batch_size else batch_size

        batch = random.sample(self._buffer, _available_batch_length)
        
        _states = np.array([_experience[0] for _experience in batch])
        _actions = np.array([_experience[1] for _experience in batch])
        _rewards = np.array([_experience[2] for _experience in batch])
        _dones = np.array([_experience[3] for _experience in batch])
        _next_states = np.array([_experience[4] for _experience in batch])

        
        
        return batch
    
    def clear(self):
        self._buffer.clear()
        self._count = 0
