#include <stdio.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ether_header *eth_header;
    struct ip *ip_header;
    struct tcphdr *tcp_header;
    char *payload;
    int payload_length;

    eth_header = (struct ether_header *) packet;

    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        // Get IP header
        ip_header = (struct ip *) (packet + sizeof(struct ether_header));

        if (ip_header->ip_p == IPPROTO_TCP) {
            // Get TCP header
            tcp_header = (struct tcphdr *) (packet + sizeof(struct ether_header) + ip_header->ip_hl * 4);

            payload = (char *) (packet + sizeof(struct ether_header) + ip_header->ip_hl * 4 + tcp_header->th_off * 4);
            payload_length = ntohs(ip_header->ip_len) - (ip_header->ip_hl * 4) - (tcp_header->th_off * 4);

            printf("Ethernet Header:\n");
            printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", eth_header->ether_shost[0],
                   eth_header->ether_shost[1], eth_header->ether_shost[2], eth_header->ether_shost[3],
                   eth_header->ether_shost[4], eth_header->ether_shost[5]);
            printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", eth_header->ether_dhost[0],
                   eth_header->ether_dhost[1], eth_header->ether_dhost[2], eth_header->ether_dhost[3],
                   eth_header->ether_dhost[4], eth_header->ether_dhost[5]);

            printf("\nIP Header:\n");
            printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
            printf("Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));

            printf("\nTCP Header:\n");
            printf("Source Port: %d\n", ntohs(tcp_header->th_sport));
            printf("Destination Port: %d\n", ntohs(tcp_header->th_dport));

            printf("\nPayload:\n");
            if (payload_length > 0) {
                // Print only a portion of payload (e.g., first 20 bytes)
                int print_length = payload_length > 20 ? 20 : payload_length;
                for (int i = 0; i < print_length; i++) {
                    printf("%02x ", (unsigned char) payload[i]);
                }
                printf("\n");
            } else {
                printf("No payload\n");
            }

            printf("-----------------------------------------\n");
        }
    }
}

int main() {
    pcap_t *handle;
    char *dev, errbuf[PCAP_ERRBUF_SIZE];

    // Find a suitable network device for sniffing
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return 1;
    }

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 1;
    }

    printf("Sniffing on device: %s\n", dev);
    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_close(handle);

    return 0;
}