minissl
=======

Mini ssl client / server implementation using public key cryptography
Usage:
======
To start Server:
server.py listen_port servercert serverprivkey {SimpleAuth, ClientAuth} payload.txt
To start Client:
client.py dst_ip dst_port clientcert clientprivkey

The path to the certifcate can be changed according to location, and also the file to be transferred after the handshake is complete.
If ClientAuth is given, server asks for the certificate of client, else it does not asks.
