from ddpg import DDPG as Agent


def loop(agent, world):
    state = world.get_state()
    action = agent.get_action(state)
    next_state, reward, done = world.act(action)
    agent.remember(state, action, reward, done, next_state)
    agent.train()


def main():
    world = World()
    agent = Agent(state_size=world.state_size, action_size=world.action_size)
    while True:
        loop(agent, world)