# SOCKS5

# uses TCP/IP and has a means of forwarding UDP
# A SOCKS server accepts incoming client connection on TCP port 1080

# SOCKS5 RFC
# https://www.ietf.org/rfc/rfc1928.txt

# Helpful post
# https://blog.zhaytam.com/2019/11/15/socks5-a-net-core-implementation-from-scratch/

# Constants
# public const byte Reserved = 0x00;
# public const byte AuthNumberOfAuthMethodsSupported = 2;
# public const byte AuthMethodNoAuthenticationRequired = 0x00;
# public const byte AuthMethodGssapi = 0x01;
# public const byte AuthMethodUsernamePassword = 0x02;
# public const byte AuthMethodIanaAssignedRangeBegin = 0x03;
# public const byte AuthMethodIanaAssignedRangeEnd = 0x7f;
# public const byte AuthMethodReservedRangeBegin = 0x80;
# public const byte AuthMethodReservedRangeEnd = 0xfe;
# public const byte AuthMethodReplyNoAcceptableMethods = 0xff;
# public const byte CmdConnect = 0x01;
# public const byte CmdBind = 0x02;
# public const byte CmdUdpAssociate = 0x03;
# public const byte CmdReplySucceeded = 0x00;
# public const byte CmdReplyGeneralSocksServerFailure = 0x01;
# public const byte CmdReplyConnectionNotAllowedByRuleset = 0x02;
# public const byte CmdReplyNetworkUnreachable = 0x03;
# public const byte CmdReplyHostUnreachable = 0x04;
# public const byte CmdReplyConnectionRefused = 0x05;
# public const byte CmdReplyTtlExpired = 0x06;
# public const byte CmdReplyCommandNotSupported = 0x07;
# public const byte CmdReplyAddressTypeNotSupported = 0x08;
# public const byte AddrtypeIpv4 = 0x01;
# public const byte AddrtypeDomainName = 0x03;
# public const byte AddrtypeIpv6 = 0x04;

# Options User must provide
# public class Socks5Options
# {
#
#     public string ProxyHost { get; }
#     public int ProxyPort { get; }
#     public string DestinationHost { get; }
#     public int DestinationPort { get; }
#     public AuthType? Auth { get; }
#     public (string Username, string Password) Credentials { get; }
#
#     public Socks5Options(string proxyHost, int proxyPort, string destHost, int destPort)
#     {
#         ProxyHost = proxyHost;
#         ProxyPort = proxyPort;
#         DestinationHost = destHost;
#         DestinationPort = destPort;
#         Auth = AuthType.None;
#     }
#
#     public Socks5Options(string proxyHost, string destHost, int destPort) : this(proxyHost, 1080, destHost, destPort) { }
#
#     public Socks5Options(string proxyHost, int proxyPort, string destHost, int destPort, string username,
#         string password) : this(proxyHost, proxyPort, destHost, destPort)
#     {
#         Auth = AuthType.UsernamePassword;
#         Credentials = (username, password);
#     }
#
#     public Socks5Options(string proxyHost, string destHost, int destPort, string username, string password) :
#         this(proxyHost, 1080, destHost, destPort, username, password)
#     { }
#
# }
#
# public enum AuthType
# {
#     None,
#     UsernamePassword
# }


# Select Auth Method
# /*
# +----+----------+----------+
# | VER | NMETHODS | METHODS |
# +----+----------+----------+
# | 1  | 1        | 1 to 255 |
# +----+----------+----------+
# */
# var buffer = new byte[4] {
#     5,
#     2,
#     Socks5Constants.AuthMethodNoAuthenticationRequired, Socks5Constants.AuthMethodUsernamePassword
# };
# await socket.SendAsync(buffer, SocketFlags.None);


# Proxy server responds with chosen method
# /*
# +-----+--------+
# | VER | METHOD |
# +-----+--------+
# | 1   | 1      |
# +-----+--------+
# */
# var response = new byte[2];
# var read = await socket.ReceiveAsync(response, SocketFlags.None);
# if (read != 2)
#     throw new SocksocketException($"Failed to select an authentication method, the server sent {read} bytes.");
#
# if (response[1] == Socks5Constants.AuthMethodReplyNoAcceptableMethods)
# {
#     socket.Close();
#     throw new SocksocketException("The proxy destination does not accept the supported proxy client authentication methods.");
# }
#
# if (response[1] == Socks5Constants.AuthMethodUsernamePassword && options.Auth == AuthType.None)
# {
#     socket.Close();
#     throw new SocksocketException("The proxy destination requires a username and password for authentication.");


import socket
# Don't want to block wihle waiting for new connections.
# So use threads and handle each new connection in threads.
import threading
# from importlib import reload # for hotreloading modules, but instances aren't affected, so they must be destroyed and remade
# usage reload(module)
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

import ssl
import random

regex = "^(?:([^:/?#]+)://)?([a-zA-Z]+|[0-9]+|[$-_@.&+]+|[!*\(\),]+|(?:%[0-9a-fA-F][0-9a-fA-F])+)(?::([0-9]+))(/.+)?"
url_parser = re.compile(regex, re.I)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # socket type is given as an argument here
s.bind(("127.0.0.1", 1080))
s.listen(1)

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

                                if requested_address[0] != "52.35.6.89" and requested_address[0] != "172.217.18.164":

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

                                    if requested_address[1] == 443: # if making a request on port 443 of target host
                                        # For HTTPS connections:
                                        # SSL handshake packet begins with b'\x16\x03\x01'


                                        # The initial handshake packet sent by the client is
                                        # a Client Hello, and it is unencrypted and can be parsed normally.

                                        # The server responds with a Server Hello packet
                                        # and sends its certificate.
                                        # This packet is also unencrypted and may be parsed notmally.

                                        # The client creates and sends a Pre-Master-Secret
                                        # encrypted with the public key from the server's certificate.
                                        # The server and client each generate the Master-Secret and session keys
                                        # based on the  Pre-Master-Secret.
                                        # This packet is encrypted, which means it must be decrypted to be parsed.



                                        # The way SSL works:
                                        #   handshake
                                        #   key exchange
                                        #   data transfer

                                        # HANDSHAKE
                                        # The SSL handshake determines what version of SSL/TLS will be used,
                                        # which cipher suite will encrypt communication,
                                        # verifies the server and may also verify the client,
                                        # and assures a secure connection for data transfer

                                        # The handshake itself is only a preparation to the actual connection
                                        # It uses asymmetric encryption (public and private key encryption system)
                                        # public encrypts, and private key decrypts
                                        # This kind of system carries too much overhead to be used constantly
                                        # So public key encryption and private key decryption is used for the handshake only,
                                        # during which, a shared key is set up and exchanged to use symmetric encryption throughout.

                                        #The handshake protocol follows these steps:
                                        # 1.  Client sends a Client Hello message to the server,
                                        #         along with the client's random value
                                        #         (also called nonce or challenge ) and
                                        #         supported cipher suites.
                                        # 2.  Server responds by sending a Server Hello message
                                        #         to the client. Server too sends a random value
                                        #         along with the Server Hello message
                                        #         to avoid replay attacks..
                                        # 3.  Server sends its Certificate to client for
                                        #         authentication and may optionally request a
                                        #         certificate from the client.
                                        # 4.  Server sends the Server Hello Done message.
                                        # 5.  If server has requested a certificate from
                                        #         the client, the client sends it.
                                        # 6.  Client creates and sends server a
                                        #         Pre-Master-Secret encrypted with the public
                                        #         key from the server's certificate.
                                        # 7.  Server and client each generate the Master-Secret
                                        #         and session keys based on the Pre-Master Secret.
                                        # 8.  Client sends Change Cipher Spec notification to
                                        #         server indicating it will start using the
                                        #         new session keys for hashing and encrypting messages.
                                        # 9.  Server sends Change Cipher Spec notification to Client.
                                        # 10. Client and server can now exchange Application Data
                                        #         over the secured channel encrypted using session key.


                                        # Client Hello message:
                                        # First byte (byte 1) b"\x16" is equivalent to 22 in decimal.
                                        # This first byte is the content-type.
                                        # 22 (or \x16) means "handshake"

                                        # Next two bytes (bytes 2,3) (b"\x03\x01") are the TLS version
                                        # b"\x03\x01" stands for TSL version 1.0

                                        # Next two bytes (bytes 4,5) are the length
                                        # b"\x02\x00" is 512

                                        # Next byte (byte 6) is handshake type
                                        # b"\x01" is Client Hello
                                        # b"\x02" is Server Hello

                                        # Next three bytes (bytes 7,8,9) are the length
                                        # b"\x00\x01\xfc" is 508

                                        # Next two bytes (bytes 10,11) are the version
                                        # b"\x03\x03" is version TLS 1.2

                                        # Next 32 bytes (bytes 12-42) are random values used for deriving keys

                                        # Next byte (byte 43) is the length of the session id

                                        # Next bytes are the session id
                                        # the number bytes in this segment for the session id is given by the prior byte.
                                        # The session id is an persistent identifier the client can use to resume the same
                                        # session later when it sends the Client Hello.

                                        # The next 2 bytes are the length of the list of cipher suites.
                                        # 2 bytes are allotted for each suite id.
                                        # So in the case of a cipher suites length of 32. There will be a list of 18 cipher suites.
                                        # For example: Cipher suite TLS_RSA_WITH_AES_128_GCM_SHA256 is b"\x00\x9c"

                                        # The next bytes are the cipher suites. The number of bytes here is given by the previous two bytes.

                                        # Next byte is the length of the list of compression methods. 1 Byte is given per compression method

                                        # The next bytes are the compression methods. The length of this segment of bytes is given by the previous byte.
                                        # b"\x00" means "no compression method"

                                        # The next two bytes are the length of the segment of bytes listing the extensions available.


                                        # You generate the CONNECT request in your SOCKS proxy
                                        # and therefore you should keep the response to this
                                        # request to yourself and not forward it to the
                                        # client. What you should do:
                                        #
                                        # If you receive the start of the SSL handshake from
                                        # the client ("\x16\x03... ") you should buffer it.

                                        # Then you create the CONNECT request and send it to
                                        # the proxy. The Host header and Proxy-Connection headers
                                        # have no meaning with CONNECT so you don't need to add them.

                                        # Read the response from the proxy to the CONNECT request.
                                        # If status code is not 200 something is wrong and you
                                        # should close the connection to the client. There is no
                                        # easy way to transfer the error information to the client.

                                        # If status code is 200 forward the buffered ClientHello
                                        # from the client to the server through the proxy and from
                                        # then on forward everything between client and
                                        # server (through the proxy tunnel).

                                        # print(ID, "attempting to upgrade client socket to ssl socket")
                                        # ssl_conn = ssl.wrap_socket(conn, ssl_version=ssl.PROTOCOL_TLS_SERVER, ciphers="ADH-AES256-SHA")

                                        # context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
                                        # context.verify_mode = ssl.CERT_NONE
                                        # context.check_hostname = False
                                        # context.set_ciphers("ADH-AES256-SHA")
                                        #
                                        # print(ID, "Beginning SSL TCP socket connection")
                                        # print(ID, "Wrapping socket using python's SSL wrapper")
                                        # ssl_forwarding_socket = context.wrap_socket(forwarding_socket)
                                        #
                                        # print(ID, "binding SSL socket")
                                        # ssl_forwarding_socket.bind(("0.0.0.0", 0))
                                        # print(ID, "connecting ssl socket to ", requested_address)
                                        # ssl_forwarding_socket.connect(requested_address)
                                        #
                                        # print(ID, "trying an SSL request to {}:{}...".format(requested_address[0],requested_address[1]))
                                        # client_handshake = conn.recv(50000)
                                        # print(ID, "client wants to send \n ::> ", client_handshake)
                                        # ssl_forwarding_socket.send(client_handshake)
                                        # v = ssl_forwarding_socket.recv(50000)
                                        # print(ID, "target host returned \n ::> ", v)

                                        print(ID, "Beginning SSL TCP socket connection")
                                        print(ID, "binding socket")
                                        forwarding_socket.bind(("0.0.0.0", 0))
                                        print(ID, "connecting socket to ", requested_address)
                                        forwarding_socket.connect(requested_address)
                                        print(ID, "connecting SSL request to {}:{}...".format(requested_address[0],requested_address[1]))
                                        print(ID, "starting loop")
                                        # first_run = True
                                        # while True:
                                        #     print(ID, "getting from client")
                                        #     client_request = conn.recv(50000) # HTTP request is seen here
                                        #     if not client_request: break
                                        #     print(ID, "got \n ::> ", client_request)
                                        #     if client_request[5:6] == b"\x01" and client_request[0:1] == b"\x16":
                                        #         print(ID, "Client sent Client Hello")
                                        #
                                        #     print(ID, "forwarding prior message to target serer ::> ", requested_address)
                                        #     forwarding_socket.send(client_request)
                                        #     client_request = None
                                        #     while True:
                                        #         # if client_request and first_run:
                                        #         #     print(ID, "client is sending \n ::> ", client_request)
                                        #         #     forwarding_socket.send(client_request)
                                        #         #     first_run = False
                                        #         print(ID, "getting data from target server ::> ", requested_address)
                                        #         forwarding_data = forwarding_socket.recv(50000)
                                        #         if not forwarding_data: break
                                        #         print(ID, "target server {}:{} sent \n ::> ".format(requested_address[0],requested_address[1]), forwarding_data)
                                        #         if forwarding_data[5:6] == b"\x02" and forwarding_data[0:1] == b"\x16":
                                        #             print(ID, "Target server sent Server Hello")
                                        #         print(ID, "forwarding above data from target server {}:{} to client".format(requested_address[0],requested_address[1]))
                                        #         conn.send(forwarding_data)
                                        #         forwarding_data = None
                                        #         # if first_run:
                                        #         #     print(ID, "getting response from client")
                                        #         #     client_request = conn.recv(50000)
                                        #     # break

                                        while True:
                                            print(ID, "getting from client")
                                            client_request = conn.recv(50000) # HTTP request is seen here
                                            if not client_request: break
                                            print(ID, "got \n ::> ", client_request)
                                            if client_request[5:6] == b"\x01" and client_request[0:1] == b"\x16":
                                                print(ID, "Client sent Client Hello")

                                            print(ID, "forwarding prior message to target serer ::> ", requested_address)
                                            forwarding_socket.send(client_request)
                                            client_request = None

                                            print(ID, "getting data from target server ::> ", requested_address)
                                            forwarding_data = forwarding_socket.recv(50000)
                                            if not forwarding_data: break
                                            print(ID, "target server {}:{} sent \n ::> ".format(requested_address[0],requested_address[1]), forwarding_data)
                                            if forwarding_data[5:6] == b"\x02" and forwarding_data[0:1] == b"\x16":
                                                print(ID, "Target server sent Server Hello")
                                            print(ID, "forwarding above data from target server {}:{} to client".format(requested_address[0],requested_address[1]))
                                            conn.send(forwarding_data)
                                            forwarding_data = None

                                    else:
                                        # NON SSL request

                                        print(ID, "Beginning NONSSL TCP socket connection")
                                        print(ID, "binding socket")
                                        forwarding_socket.bind(("0.0.0.0", 0))
                                        print(ID, "connecting socket to ", requested_address)
                                        forwarding_socket.connect(requested_address)
                                        print(ID, "connecting nonSSL request to {}:{}...".format(requested_address[0],requested_address[1]))
                                        print(ID, "starting loop")
                                        while True:
                                            print(ID, "getting from client")
                                            client_request = conn.recv(50000) # HTTP request is seen here
                                            if not client_request: break
                                            print(ID, "got \n ::> ", client_request)

                                            print(ID, "forwarding prior message to target serer ::> ", requested_address)
                                            forwarding_socket.send(client_request)
                                            while True:
                                                print(ID, "getting data from target server ::> ", requested_address)
                                                forwarding_data = forwarding_socket.recv(50000)
                                                if not forwarding_data: break
                                                print(ID, "target server {}:{} sent \n ::> ".format(requested_address[0],requested_address[1]), forwarding_data)
                                                print(ID, "forwarding above data from target server {}:{} to client".format(requested_address[0],requested_address[1]))
                                                conn.send(forwarding_data)
                                            break
                                else:
                                    if requested_address[0] == "52.35.6.89":
                                        print(ID, "blocked request to moxilla telemetry server")
                                    elif requested_address[0] != "172.217.18.164":
                                        print(ID, "blocked request to google server")
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
while 1:
    conn, addr = s.accept() # blocking while waits for connection
    # s.accept returns a tuple of (conn, addr)
    # conn is a new socket object, useable to send and receive data on the connection
    # addr is a tuple that contains (remote address, port)
    # This means that each new conn is a new socket to handle the connection.
    threading.Thread(target=handleConnection, args=(conn, addr)).start()


# b'CONNECT improving.duckduckgo.com:443 HTTP/1.1\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:83.0) Gecko/20100101 Firefox/83.0\r\nProxy-Connection: keep-alive\r\nConnection: keep-alive\r\nHost: improving.duckduckgo.com:443\r\n\r\n'

# connect and forward the connection
