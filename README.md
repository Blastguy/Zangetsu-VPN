# Zangetsu: a simple QUIC-based VPN

CS 6262 project, Fall 2023
Georgia Institute of Technology

Remember to create new public/private key pairs, this is a public GitHub repo!

Command to run the Server counterpart:
```
sudo python3 VPN_Zangetsu.py --server --port 443 -k private.key -c pub.pem
```

Command to run the Client counterpart:
```
sudo python3 VPN_Zangetsu.py --host [Host IP] --port 443 -i
```

Extra Commands:
Before creating the server or client make sure that the tunnel or the client tunnel is not already existing on the system. To remove:
```
sudo ip link del [Tunnel to be deleted]
```
