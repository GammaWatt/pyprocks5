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

regex = "^(?:([^:/?#]+)://)?([a-zA-Z]+|[0-9]+|[$-_@.&+]+|[!*\(\),]+|(?:%[0-9a-fA-F][0-9a-fA-F])+)(?::([0-9]+))(/.+)?"
url_parser = re.compile(regex, re.I)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # socket type is given as an argument here
s.bind(("127.0.0.1", 1080))
s.listen(1)

def handleConnection(conn, addr):
    print(addr, conn)
    resp = conn.recv(3) # receive 3 bytes
    print(resp) # blocking while waits for message
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

                                returned_response = b"".join([b"\x05\x00\x00\x01", returned_address, returned_port])

                                # conn.send(b"\x05\x00\x00\x01", <B_HOST>, <B_PORT>")
                                print("sending")
                                print(conn.send(returned_response))
                                print("bytes")
                                print("creating socket")
                                forwarding_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                forwarding_socket.bind(("0.0.0.0", 0))
                                forwarding_socket.connect(requested_address)
                                print("starting loop")
                                while True:
                                    print("getting from client")
                                    client_request = conn.recv(50000) # HTTP request is seen here
                                    if not client_request: break
                                    print(client_request)

                                    print("forwarding prior message to target serer", requested_address)
                                    forwarding_socket.send(client_request)
                                    while True:
                                        print("getting data from target server", requested_address)
                                        forwarding_data = forwarding_socket.recv(50000)
                                        if not forwarding_data: break
                                        print("target server {}:{} sent".format(requested_address[0],requested_address[1]))
                                        print(forwarding_data)
                                        print("forwarding above data from target server {}:{} to client".format(requested_address[0],requested_address[1]))
                                        conn.send(forwarding_data)
                                    break

                                    # Works for HTTP connections As if right now

                                    # For HTTPS connections:
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



while 1:
    conn, addr = s.accept() # blocking while waits for connection
    # s.accept returns a tuple of (conn, addr)
    # conn is a new socket object, useable to send and receive data on the connection
    # addr is a tuple that contains (remote address, port)
    # This means that each new conn is a new socket to handle the connection.
    threading.Thread(target=handleConnection, args=(conn, addr)).start()


# b'CONNECT improving.duckduckgo.com:443 HTTP/1.1\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:83.0) Gecko/20100101 Firefox/83.0\r\nProxy-Connection: keep-alive\r\nConnection: keep-alive\r\nHost: improving.duckduckgo.com:443\r\n\r\n'

# connect and forward the connection
