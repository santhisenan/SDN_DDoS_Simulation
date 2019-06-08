# DDoS Simulation in a Software Defined Network
 This project aims to provide a basic framework for DDoS mitigation using Deep reinforcement learning. The network is implemented using Mininet (based on Software defind networking). 
## Getting Started
Clone the repository 
```
git clone https://github.com/santhisenan/SDN_DDoS_Simulation.git
```
## Prerequisites
Install dependencies

* Install Mininet
* Install OpenVSwitch
* Install Ryu 
* Install Tensorflow
* Install Keras

* Clone ryu repository and copy  ryu/ryu folder to SDN_DDoS_Simulation root

## Testing
Modify simple_tree_top.py according to test purpose
```
cd SDN_DDoS_Simulation
python simple_tree_top.py
```
Open a new Terminal tab
```
PYTHONPATH=. ryu/ryu/bin/ryu-manager main.py
```
## Running
```
cd SDN_DDoS_Simulation
python tree_topology.py
```
Open a new Terminal tab
```
PYTHONPATH=. ryu/ryu/bin/ryu-manager main.py
```

## Built With

* [Ryu Controller](https://osrg.github.io/ryu/) - Controller Framework for SDN
* [Mininet](https://maven.apache.org/) - SDN simulator
* [OpenVSwitch](http://mininet.org/) - Custom switch for SDN
* [Tensorflow](https://www.tensorflow.org/) - Deep Learning Framework
* [Keras](https://keras.io/) - Deep Learning Framework


## Authors

* Santhisenan Ajith
* Vishnu Kaimel
* Mohammed Musthafa K
* Ankith Madusudanan

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details


