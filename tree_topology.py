from mininet.net import Mininet
from mininet.topolib import TreeTopo

tree_topo = TreeTopo(depth=2, fanout=2)
net = Mininet(topo=tree_topo)
net.start()


net.stop()
