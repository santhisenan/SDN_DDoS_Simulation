#!/bin/bash

# MINIMUM_BANDWIDTH=6
# MAXIMUM_BANDWIDTH=10

# FILE="./bandwidth_rate.txt"
# truncate -s 0 $FILE

# random_rate=$(($MINIMUM_BANDWIDTH+RANDOM%($MAXIMUM_BANDWIDTH-$MINIMUM_BANDWIDTH))).$((RANDOM%999))
# echo $random_rate>>$FILE

# echo "Cleaning mininet"
killall python
sudo mn -c

PYTHONPATH=. ryu/bin/ryu-manager app.py &
sleep 10s
sudo python tree_topology.py
