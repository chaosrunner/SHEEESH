#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>

void inspectSOCKS5(const u_char *packet, int length) {
    if (length < 10) {
        return;
    }

    if (packet[0] == 0x05 && packet[1] == 0x01) {
        unsigned char ip[16];
        unsigned short port;

        if (packet[3] == 0x01) { // IP V4 address
            ip[0] = packet[4];
            ip[1] = packet[5];
            ip[2] = packet[6];
            ip[3] = packet[7];
            port = (packet[8] << 8) | packet[9];
            printf("SOCKS5 connection found from %d.%d.%d.%d:%d\n", ip[0], ip[1], ip[2], ip[3], port);
        } else if (packet[3] == 0x03) { // DOMAINNAME
            int domainLength = packet[4];
            char domain[256];
            memset(domain, 0, sizeof(domain));
            if (length < domainLength + 5) {
                return;
            }
            memcpy(domain, &packet[5], domainLength);
            port = (packet[5 + domainLength] << 8) | packet[5 + domainLength + 1];
            printf("SOCKS5 connection found from %s:%d\n", domain, port);
        } else if (packet[3] == 0x04) { // IP V6 address
            return; // Not handling IPv6 in this example
        } else {
            return;
        }
    }
}

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    inspectSOCKS5(packet, pkthdr->caplen);
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        return 1;
    }

    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_close(handle);
    return 0;
}
