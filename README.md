# C-ARP-Spoofing
ARP response implementation in c that allows you to perform ARP spoofing.

## Usage
Enable IP-Forwarding<br/>
`$ sudo bash -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'`<br/>
Compile `arp_spoofing.c` (e.g `gcc arp_spoofing.c -o arp_spoofing`).<br/>
run `arp_spoofing` as follows:<br/>
`$ sudo ./[File] [Destination IP] [Source IP] [Interface]`<br/>
In order to perform ARP spoofing, insert the spoofed address to the `[Source IP]` parameter.<br/>

![GIF-Arp-spoofing](https://user-images.githubusercontent.com/91408265/201964289-c4f60358-ef77-436d-9a5f-1ec53a45d4c4.gif)

## Ethical Notice
The use of code contained in this repository, either in part or in its totality, for engaging targets without prior mutual consent is illegal. It is the end-user's responsibility to obey all applicable local, state and federal laws. In brief, do not use it with evil intent.
