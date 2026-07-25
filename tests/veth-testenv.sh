#!/bin/bash
sudo ip netns del attacker 2>/dev/null || true
sudo ip link del veth-ward 2>/dev/null || true

# Create namespace
sudo ip netns add attacker

# Create veth pair
sudo ip link add veth-ward type veth peer name veth-atk

# Move one end into namespace
sudo ip link set veth-atk netns attacker

# Address + bring up main side
sudo ip addr add 10.200.0.1/24 dev veth-ward
sudo ip link set veth-ward up

# Address + bring up namespace side
sudo ip netns exec attacker ip addr add 10.200.0.2/24 dev veth-atk
sudo ip netns exec attacker ip link set veth-atk up
sudo ip netns exec attacker ip link set lo up

# Verify
sudo ip netns exec attacker ping -c2 10.200.0.1