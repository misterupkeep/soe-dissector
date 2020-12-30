# soe-dissector
Wireshark dissector(s) for Sony Online Entertainment's Reliable UDP
protocol (version string `CGAPI_527`).

Currently only a Lua version exists, though a C version ought to be
added at some point.

## Dependencies
The Lua dissector depends on `zlib` for decompressing packets.
Check the Lua version on your Wireshark; you can use `luarocks` to
install it:
```sh
luarocks-5.2 install zlib
```

## Installation
Place or symlink the `.lua` file onto Wireshark's Lua plugin path. You
can find out all the directories Wireshark scans in `Help > About >
Folders`, or run:
```sh
ln -s ~/.local/lib/wireshark/plugins/3.4 ./lua/soe-dissector.lua
```

## The SOE RUDP protocol
Research (inconclusive research) shows that Jeff Petersen, while
working on the game Cosmic Rift, designed a Layer 7 protocol for it.

This protocol serves merely as a transport layer protocol for game
data. It's designed to be reliable, secure, and compact. However, it
accomplishes only one out of three.

For one, it's sent over UDP, making reliability actually challenging,
in that it has to be manually implemented. It's done by incrementing
package sequence numbers, and receiving ACKs for each sequence number.
In case of out of order packets, the recipient sends `OUT_ORDER_PKT`
packets for each out of order sequence number, so that they, along
with the missing packets, can be resent.

The encryption is optionally 'enabled' during the two-way handshake.
As far as I can tell, it uses the CRC seed exchanged during the
handshake as a XOR pad. However, that seed is sent unencumbered by any
encryption, meaning that anyone intercepting the `SESSION_REPLY` packet
would be able to eavesdrop.

Not all is bad though (and I'm sure these design decisions made sense
at the time). Packets with data too large to fit into the client's
input buffer (communicated during handshake) will get 'fragmented'
into several. Furthermore, if a series of small packets (i.e
`OUT_ORDER_PKT` or `ACK`) need to be sent, they can be grouped
together into a `SOE_MULTI_SOE` packet.

In the `SESSION_REPLY` packet, the server warns the client of possible
use of (and support for) compression. Subsequent data/fragmented/multi
packets will have on them a compression flag indicating if the payload
is compressed (for which DEFLATE/gzip/zlib is used).

What is interesting is that the protocol supports 4 'channels' for
sending data: Each data-containing packet is tagged to which channel
it's for. A cute idea that, sadly, doesn't seem to be used in any game,
that I can find.

### Remark about protocol version specificity
While the layout between revisions of the SOE RUDP protocol changes
little, this dissector will most likely only work for protocol
revision with string revision `CGAPI_527`, which itself seems to be
what Free Realms uses.
