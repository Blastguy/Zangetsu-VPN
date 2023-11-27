# Zangetsu: a simple QUIC-based VPN

CS 6262 project, Fall 2023
Georgia Institute of Technology

Command to run the Server counterpart:
```
sudo python3 VPN_Zangetsu.py --server --port 3001 -k private.key -c pub.pem
```

Command to run the Client counterpart:
```
sudo python3 VPN_Zangetsu.py --host [Host IP] --port 3001 -i
```

Extra Commands:
Before creating the server or client make sure that the tunnel or the client tunnel is not already existing on the system. To remove:
```
sudo ip link del [Tunnel to be deleted]
```

Improper termination work pending.
