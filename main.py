
# The following function performs the steps in RL pipeline - 
# 1) get a state from the environment
# 2) pass the state to the agent and get the action to be performed 
# 3) perform the action 
# 4) get the reward
# 5) repeat
def perform_rl(env, agent):
    state = env.get_state()
    action = agent.get_action(state)
    next_state, reward, done = env.act(action)
    agent.remember(state, action, reward, done, next_state)
    agent.train()

def main():
    # env = Env()
    # agent  = DDPGAgent()
    while True:
        # perform_rl(env, agent)
