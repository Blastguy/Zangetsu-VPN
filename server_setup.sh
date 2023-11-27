#!/bin/bash

#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!#
#Bash Script implementing Forwarding, Postrouting and Masquerading..
#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!#


# List all network interfaces
echo "Available network interfaces:"
ifconfig -a | awk '!/lo/{print $1}' | sed 's/:$//'

# Prompt the user to select a network interface
read -p "Enter the desired network interface: " selected_interface

# If the user didn't enter anything, default to 'eth0'
if [ -z "$selected_interface" ]; then
    selected_interface="eth0"
fi

#Forward the traffic from the client through the tunnel_server interface to the out interface of the server.
sudo iptables -A FORWARD --in-interface tunnel_server --out-interface "$selected_interface" -j ACCEPT

#After resolving the client's request, forward the traffic from server's local interface to tunnel_server interface to the client.
sudo iptables -A FORWARD --out-interface tunnel_server --in-interface "$selected_interface" -j ACCEPT

#This command appends a rule to the end of the FORWARD chain, allowing incoming packets on the wireless interface "$interface" to be accepted and forwarded.
sudo iptables -A FORWARD -i "$selected_interface" -j ACCEPT

#This command appends a rule to the end of the FORWARD chain, allowing outgoing packets on the wireless interface "$interface" to be accepted and forwarded.
sudo iptables -A FORWARD -o "$selected_interface" -j ACCEPT

#This command sets up a NAT rule for the POSTROUTING chain, specifically for the outgoing packets on the wireless interface "$interface" 
#The packets leaving through this interface will undergo NAT, and their source addresses will be masqueraded, allowing multiple internal devices to share a single external IP address.
sudo iptables -t nat -A POSTROUTING --out-interface "$selected_interface" -j MASQUERADE

#This command sets up another NAT rule for the POSTROUTING chain, but this time for the outgoing packets on a different interface, "tunnel_server". 
#This commannd masquerades the source addresses of outgoing packets on this interface.
sudo iptables -t nat -A POSTROUTING --out-interface tunnel_server -j MASQUERADE

sudo sysctl net.ipv4.ip_forward=1

echo "Using network interface: $selected_interface"
