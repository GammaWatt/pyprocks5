# SOCKS5

# uses TCP/IP and has a means of forwarding UDP
# A SOCKS server accepts incoming client connection on TCP port 1080

# SOCKS5 RFC
# https://www.ietf.org/rfc/rfc1928.txt

# Helpful post
# https://blog.zhaytam.com/2019/11/15/socks5-a-net-core-implementation-from-scratch/

# Another helpful post 
# (The comments about the bytes in the handshake 
# packets are copied / paraphrased from this post)
# https://medium.com/@vanrijn/an-overview-of-the-ssl-handshake-3885c37c3e0f

import socket
# Don't want to block wihle waiting for new connections.
# So use threads and handle each new connection in threads.
import threading
# import multiprocessing # spawns independent process which tries to copy sockets and such which errors out, since they try to rebind to the same addresses and ports.
# Python threads are good for IO bound tasks, like waiting for network respnses or user input.
# Python multiprocessing is good for CPU bound tasks, like calculating a sum or processing data.
# threads ruin performance for CPU bound tasks
# Unless the thread is created as a daemon thread, Python waits for all threads to close before exiting.

import requests

import re

# Influences on the regex I'm using
# http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+
# ^(([^:/?#]+):)?(//([^/?#]*))?([^?#]*)(\?([^#]*))?(#(.*))?
# ^(?:([a-zA-Z]+?)://)?((?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+)

# Almost what I want (almost perfect)
# The very last bit (the (/.+)) should be more specific, but I couldn't get it to work.
# ^(?:([^:/?#]+)://)?([a-zA-Z]+|[0-9]+|[$-_@.&+]+|[!*\(\),]+|(?:%[0-9a-fA-F][0-9a-fA-F])+)(?::([0-9]+))(/.+)?

import random
import time

regex = "^(?:([^:/?#]+)://)?([a-zA-Z]+|[0-9]+|[$-_@.&+]+|[!*\(\),]+|(?:%[0-9a-fA-F][0-9a-fA-F])+)(?::([0-9]+))(/.+)?"
url_parser = re.compile(regex, re.I)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # socket type is given as an argument here
s.bind(("127.0.0.1", 1080))
s.listen(1)

BUFFER_SIZE = 4098

blacklist = {
    # "52.35.6.89",       # mozilla telemetry
    # "172.217.18.164",    # google
}

# "143.204.226.112" # cloudfront servers a ton of websites link to

SHOW_PACKETS = 0

def pipeToSocket(src, dest, buffer_size, ID):
    src.setblocking(0)
    dest.setblocking(0)
    # Disabling blocking makes it so data is
    # read from the socket (if available) and returned immediately.
    # If not data is found, an error is produced.
    packets_sent = False
    while 1:
        try:
            got = src.recv(buffer_size)
            if got and SHOW_PACKETS:
                print("sending data ::> ", got)
            else:
                # empty b"" but important to send in order to complete communication
                pass
            bytes_sent = dest.send(got)
            if bytes_sent and SHOW_PACKETS:
                print("sent ", bytes_sent, " bytes.")
            else:
                # same thing
                pass
            packets_sent = True
        except:
            # if not packets_sent:
            #     print(ID, "no data to send")
            # else:
            #     print(ID, "no more data to send")
            break
    src.setblocking(1)
    dest.setblocking(1)
    return packets_sent


def handleConnection(conn, addr):
    ID = random.randint(1000, 9999)

    print(ID, addr, conn)
    resp = conn.recv(3) # receive 3 bytes
    print(ID, resp) # blocking while waits for message
    # Initial packet sent by clientis b"\x05\x01\x00"
    # \x05 is socks version (5)
    # \x01 is number of auth methods client supports
    # \x00 can have lots of bytes (this is one (and means no auth), but could be followed by more). Each byte is an auth method.
    #       0x00: No authentication
    #       0x01: GSSAPI
    #       0x02: Username/password
    #       0x03–0x7F: methods assigned by IANA
    #       0x80–0xFE: methods reserved for private use
    # Server picks the auth method to use


    # How to know if it's the first packet or subsequent packet??
    if resp[0:1] == b"\x05":
        if resp[1:2] == b"\x01":
            if resp[2:3] == b"\x00":
                conn.send(b'\x05\x00')
                # This means socks5 (first byte)
                # and auth method 0 (second byte)
                # auth method 0 means no auth

                resp = conn.recv(22) # 22 bytes
                # Since this function is passed to threads, this line has this thread wait
                # for the next request from the client and store it in resp

                # second packet now received from the client (e.g (0x05, 0x01, 0x00, 0x03, <B_HOST>, <B_PORT>))
                # b"\x05\x01\x00\x014\x95\xf6'\x00P"

                # Second byte is \x01, which is an instruction.
                # 0x01: establish a TCP/IP stream connection == "CONNECT"
                # 0x02: establish a TCP/IP port binding == "BIND"
                # 0x03: associate a UDP port == "UDP ASSOCIATE"

                # third byte \x00 must be \x00.
                # The third byte here just always had to be \x00, and only 1 byte

                # Fourth byte \x01 is address type of desired host and should be one byte
                # 0x01: IPv4 address, followed by 4 bytes IP == "IP V4 address"
                # 0x03: Domain name, 1 byte for name length, followed by host name == "DOMAINNAME"
                # 0x04: IPv6 address, followed by 16 bytes IP == "IP V6 address"

                # In this case, \x01 is for an IPv4 address
                # So the following 4 bytes are b"4" b"\x95" b"\xf6" and b"'"

                # The last 2 bytes are the port number. b"\x00" b"P"

                if resp[0:1] == b"\x05":
                    # SOCKS5 connection
                    if resp[1:2] == b"\x01":
                        # Establishing steam connection
                        if resp[2:3] == b"\x00":
                            # Required byt
                            if resp[3:4] == b"\x01":
                                # IPv4 address
                                requested_IPv4_address = ".".join(
                                    [ str(i) for i in [
                                        int.from_bytes(resp[4:5], "big"),
                                        int.from_bytes(resp[5:6], "big"),
                                        int.from_bytes(resp[6:7], "big"),
                                        int.from_bytes(resp[7:8], "big")
                                        ]
                                    ]
                                )
                                requested_port = int.from_bytes(resp[8:10], "big")

                                requested_address = (requested_IPv4_address, requested_port)

                                if requested_address[0] not in blacklist:

                                    returned_address = bytes([int(i) for i in requested_address[0].split(".")])
                                    returned_port = int.to_bytes(requested_address[1], 2, byteorder="big")

                                    # So, after we parse that packet,
                                    # SOCKS proxy sends back the request packet (0x05, 0x00, 0x00, 0x01, <B_HOST>, <B_PORT>).
                                    # This is for the status of the request by the client to the proxy:-
                                    #
                                    # The Second Byte 0x00 is the status field. It is one byte. Meaning the request was granted.
                                    # The Third Byte 0x00 is a reserved byte. It must be 0x00 and 1 byte.
                                    # The Fourth Byte 0x01 is the address type of desired HOST and 1 byte. In case of CONNECT,
                                    #   this is followed by the binded IP address for the desired HOST, to give the client the
                                    #   detail of the DNS resolution.
                                    # The last Byte is port number in a network byte order, 2 bytes
                                    #
                                    # After this, the connection takes place all the coming data from client A is transferred
                                    #   to client B and vice versa. This way the SOCKS proxy works as a general framework proxy
                                    #   and handle most PROTOCOL with its security features.

                                    # \x05 == SOCKS5
                                    # \x00 == request granted
                                    # \x00 == reserved, must always be \x00 and only 1 byte
                                    # \x01 == address type (given to us earlier, in the second packet, so we're just regurgitating it back to the client)
                                    # B_HOST == IP of target host. \x01 connection type (IPv4 address) means we just regurgitate it back to the client
                                    # B_PORT == PORT of target host. We just send it back to the client.

                                    # We can use this server to remap routes between IP addresses and ports, if desired.
                                    # But if we want the proxy to be transparent, we just forward the connections as is.

                                    # Works for HTTP connections As if right now

                                    # conn.send(b"\x05\x00\x00\x01", <B_HOST>, <B_PORT>")
                                    returned_response = b"".join([b"\x05\x00\x00\x01", returned_address, returned_port])
                                    bytes_sent = conn.send(returned_response)
                                    print(ID, "sent {} bytes to client".format(bytes_sent))
                                    print(ID, "creating socket")
                                    forwarding_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)





                                    print(ID, "binding socket")
                                    forwarding_socket.bind(("0.0.0.0", 0))
                                    print(ID, "connecting socket to ", requested_address)
                                    forwarding_socket.connect(requested_address)
                                    print(ID, "connecting request to {}:{}...".format(requested_address[0],requested_address[1]))

                                    # print(ID, "starting loop")
                                    seconds = 0
                                    timeout = 64
                                    now = time.clock()
                                    while True:
                                        # print(ID, "Forwarding from client to target host")
                                        packets_sent_to_server = pipeToSocket(conn, forwarding_socket, BUFFER_SIZE, ID)
                                        # if packets_sent_to_server:
                                        #     print("packets sent to server")
                                        # else:
                                        #     print("no packets available from client to send to server")

                                        # print(ID, "Forwarding from target server to client")

                                        packets_sent_to_client = pipeToSocket(forwarding_socket, conn, BUFFER_SIZE, ID)
                                        # if packets_sent_to_client:
                                        #     print("packets sent to client")
                                        # else:
                                        #     print("no packets available from server to send to client")

                                        if packets_sent_to_server or packets_sent_to_client:
                                            seconds = 0
                                            now = time.clock()
                                        else:
                                            if int(time.clock() - now) > timeout:
                                                break

                                else:
                                    print(ID, "blocked request to {} ({})".format(requested_address[0], blacklist[requested_address[0]]))
                            else:
                                # domain name or ipv6 address
                                pass
                        else:
                            # invalid byte
                            pass
                    else:
                        # wants TCP port binding or UDP port
                        pass
                else:
                    # Not a SOCKS5 request
                    pass
            else:
                # Client wants to use an auth method I didn't put in
                # 0x00: No authentication
                # 0x01: GSSAPI
                # 0x02: Username/password
                # 0x03–0x7F: methods assigned by IANA
                # 0x80–0xFE: methods reserved for private use
                pass
        else:
            # I don't like this client. It doesn't support exactly one auth method
            pass
    else:
        # Client isn't socks5 client
        pass


# socket.setdefaulttimeout(15)
def listen():
    socket.setdefaulttimeout(64)
    while 1:
        conn, addr = s.accept() # blocking while waits for connection
        # s.accept returns a tuple of (conn, addr)
        # conn is a new socket object, useable to send and receive data on the connection
        # addr is a tuple that contains (remote address, port)
        # This means that each new conn is a new socket to handle the connection.
        threading.Thread(target=handleConnection, args=(conn, addr)).start()
        # multiprocessing.Process(target=handleConnection, args=(conn, addr)).start()

threading.Thread(target=listen).start()
# multiprocessing.Process(target=listen).start()

while 1:
    usrString = input("add/remove address from blacklist: ")
    usrString = usrString.split(" ")
    if usrString[0].lower == "add":
        desc = input("please give a name for this IP")
        blacklist[usrString[1]] = desc
        print("IP {} added to blacklist".format(usrString[1]))
    elif usrString[0].lower == "remove":
        blacklist.remove(usrString[1])
        print("IP {} removed from blacklist".format(usrString[1]))
    elif usrString[0].upper == "SHOWPACKETS":
        if usrString[1] == "0":
            SHOW_PACKETS = 0
        else:
            SHOW_PACKETS = 1
