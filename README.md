# mylittlenet

User-space networking stack implemented in Python for fun and giggles.

## Why?

I've been working as a system administrator/network engineer for a while now, but I've never really understood how the whole stack works in detail.

I have educated guesses from reading RFCs and experiences at work, but I've never really implemented anything from the ground up.

Besides, the best way to learn how anything works is to implement it yourself, right?

## Why Python?

While professionally I have frustrations with Python (especially in production or at scale), it is still a comfortable language for prototyping and getting something up and running quickly.

Originally, I tried to implement this in Zig, but I found myself spending more time fighting the language than actually implementing the networking stack.

So, Python it is.

## Goals

_Not in any particular order_

- [x] Ethernet
- [x] ARP
- [x] IPv4 (w/o fragmentation)
- [x] ICMPv4 Echo Request/Reply
- [ ] IPv4 fragmentation/reassembly
- [ ] ICMPv4 Unreachable
- [ ] UDP
  - [ ] UDP echo server
- [ ] TCP
  - [ ] TCP echo server
- [ ] Static routing
- [ ] Running applications on top of the stack / Shell
- [ ] Ping

### Stretch goals

Are these ambitious? Yes.

Do I know what I'm doing? No.

Will I get to them? Lets be honest, probably not.

- [ ] DNS client
- [ ] DNS server
- [ ] HTTP client

#### I really doubt I'll get to these...

- [ ] HTTP server
- [ ] DHCP client
- [ ] DHCP server
- [ ] Dynamic routing: RIP
- [ ] Dynamic routing: OSPF
- [ ] Dynamic routing: BGP

### Non-goals

- IPv6
- Anything "modern"
  - Let's keep it simple and old-school

## References used

- [Saminiir's Let's code a TCP/IP stack series](https://www.saminiir.com/)
  - [Part 1: Ethernet and ARP](https://www.saminiir.com/lets-code-tcp-ip-stack-1-ethernet-arp/)
  - [Part 2: IPv4 and ICMPv4](https://www.saminiir.com/lets-code-tcp-ip-stack-2-ipv4-icmpv4/)
- [RFC 791: Internet Protocol](https://tools.ietf.org/html/rfc791)
- [RFC 792: Internet Control Message Protocol](https://tools.ietf.org/html/rfc792)
- [RFC 826: Ethernet Address Resolution Protocol](https://tools.ietf.org/html/rfc826)
