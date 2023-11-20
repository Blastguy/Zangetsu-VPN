#!/bin/bash

# Delete existing default
sudo ip route delete default

# Add new default as tunnel
sudo ip route add default via 10.10.10.1 dev mytunnel

# If 2 defaults exist after this then again remove the old default as keep only the tunnel active
# sudo ip route delete default via [your default IP address]

# While running if permission denied
chmod +x client_setup.sh