from mininet.net import Mininet
from mininet.topolib import TreeTopo
from mininet.node import Controller, OVSKernelSwitch, RemoteController
import time

tree_topo = TreeTopo(depth=2, fanout=2)
net = Mininet(topo=tree_topo, controller=RemoteController)
net.start()

# for i in range(20):
# time.sleep(10)
# net.pingAll()
h1 = net.hosts[0]
result = h1.cmd('hping3 -1 --flood  10.0.0.4')
print(result)
# net.stop()
