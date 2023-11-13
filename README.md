# Zangetsu: a simple QUIC-based VPN

CS 6262 project, Fall 2023
Georgia Institute of Technology

Command to run the Server counterpart:
```
sudo python3 VPN_Zangetsu.py --server --port 443 -key private.key -c pub.pem
```

Command to run the Client counterpart:
```
sudo python3 VPN_Zangetsu.py --client --host [Host IP] --port 443 -k
```
