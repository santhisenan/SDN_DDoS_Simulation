from mininet.net import Mininet
from mininet.topolib import TreeTopo
from mininet.node import Controller, RemoteController,OVSSwitch
import time

tree_topo = TreeTopo(depth=1, fanout=2)
net = Mininet(topo=tree_topo, controller=RemoteController,switch=OVSSwitch)
net.start()

h1 = net.hosts[0]
h2 = net.hosts[1]
while True:
    print("Episode")
    h1.cmd('timeout 10s hping3 --faster --udp 10.0.0.2')
    # time.sleep(10)
    h1.cmd('killall hping3')
    # time.sleep(2)
    