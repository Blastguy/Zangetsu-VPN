#!/bin/bash

#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!#
#Bash Script implementing Forwarding, Postrouting and Masquerading..
#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!#

#Forward the traffic from the client through the mytun_serv interface to the out interface of the server.
#Out interface varies for every system, make sure to check and replace "wlp0s20f3"
sudo iptables -A FORWARD --in-interface mytun_serv --out-interface wlp0s20f3 -j ACCEPT

#After resolving the client's request, forward the traffic from server's local interface to mytun_serv interface to the client.
#In interface varies for every system, make sure to check and replace "wlp0s20f3"
sudo iptables -A FORWARD --out-interface mytun_serv --in-interface wlp0s20f3 -j ACCEPT

#This command appends a rule to the end of the FORWARD chain, allowing incoming packets on the wireless interface "wlp0s20f3" to be accepted and forwarded.
sudo iptables -A FORWARD -i wlp0s20f3 -j ACCEPT

#This command appends a rule to the end of the FORWARD chain, allowing outgoing packets on the wireless interface "wlp0s20f3" to be accepted and forwarded.
sudo iptables -A FORWARD -o wlp0s20f3 -j ACCEPT

#This command sets up a NAT rule for the POSTROUTING chain, specifically for the outgoing packets on the wireless interface "wlp0s20f3." 
#The packets leaving through this interface will undergo NAT, and their source addresses will be masqueraded, allowing multiple internal devices to share a single external IP address.
sudo iptables -t nat -A POSTROUTING --out-interface wlp0s20f3 -j MASQUERADE

#This command sets up another NAT rule for the POSTROUTING chain, but this time for the outgoing packets on a different interface, "mytun_serv." 
#This commannd masquerades the source addresses of outgoing packets on this interface.
sudo iptables -t nat -A POSTROUTING --out-interface mytun_serv -j MASQUERADE

sudo sysctl net.ipv4.ip_forward=1

chmod +x server_setup.sh