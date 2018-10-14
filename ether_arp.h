#include <cstdlib>
#include <stdio.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <libnet.h>
#include <pcap.h>

#pragma pack(push, 1)
typedef struct ethernet_arp{
    struct libnet_ethernet_hdr eth_hdr;
    struct libnet_arp_hdr arp_hdr;
    uint8_t sdr_hardware_adr[6];
    uint8_t sdr_protocol_adr[4];
    uint8_t trg_hardware_adr[6];
    uint8_t trg_protocol_adr[4];   
}ethernet_arp;
#pragma pack(pop)