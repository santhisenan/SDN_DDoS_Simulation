from mininet.net import Mininet
from mininet.topolib import TreeTopo
from mininet.node import Controller, OVSKernelSwitch, RemoteController,OVSSwitch
import time
import random

# from random import choice
import threading

tree_topo = TreeTopo(depth=1, fanout=2)
net = Mininet(topo=tree_topo, controller=RemoteController,switch=OVSSwitch)

net.start()



attacking_host_id = 1
attacking_host = net.hosts[attacking_host_id]

h1 = net.hosts[0]
h2 = net.hosts[1]


#attacking_host.cmd("hping3 -a 10.1.1.1 10.0.0.1")


time.sleep(100)
net.stop()
