# LICENSE SUMMARY
I dunno. Just don't act like you wrote this.

I read a few blog posts and reference materials, learned how this 
stuff works at a conceptual level and how it works in a general sense 
and built it from there with a lot of trial and error.

# USAGE

python server.py

# Extent of functionality

This thing completes the initial handshake with the client and forwards everything between the client and its target host address after that.

It does not handle any authentication methods, it does no checking, it does no packet inspection (aside from maybe checking IPv4 addresses for blacklisting), and it does not handle IPv6 or domain names.

It seems to work ok (although quite slow) for regular web pages, but I couldn't get youtube to load.

This thing is really heavy on the CPU, likely due to a lot of empty activity in reading empty sockets and sending empty data while it waits for connections on both sides (tried blocking the sockets and waiting for data but, most of the time, communication just stopped and the connection would fail)

Also, because there is no packet inspection, and it would have to either steal the browser private key (in real time) or break SSL encryptions for any secured requests (which is most browsing activity today), there is no way that I know of to know exactly when communications actually end.

I just wanted to write a simple, proof of concept, proxy so I could learn about sockets as well as watch, and block, unwanted connections my computer may be making. And it never dawned on me to just use Wireshark and a hosts file.... or some other equivalent.

While it was possible to have the proxy serve as a MITM on my computer, (and pose as the client making SSL connections to servers while simultaneously posing as the SSL server sending certificates to the client) it was not only beyond the scope of what I wanted to do with this thing, but I also wanted my browser to see the original server certificates instead of seeing my proxy cert. I wasn't about to start implementing the whole certificate checker system for validating whether the certificate was trustworthy or not, along with those other security features browsers today already bring with them.

I wanted the proxy server to be completely invisible, as far as the client is concerned.
Decrypting the SSL communications, as would have been ideal, while maintaining that invisibility would require somehow stealing the private keys (at connection time) of each of the servers the client tries to connect to every time. That's more trouble than it's worth... and could make some people angry.

I also tried to make it possible to toggle certain options and edit the blacklist while the server is running, but it doesn't seem to work...
