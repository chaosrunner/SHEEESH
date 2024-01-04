#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

void inspectSOCKS5(const u_char *packet, int length) {
    if (length < 10) {
        return;
    }

    // Check for SOCKS5 identification
    if (packet[0] == 0x05 && packet[1] == 0x01) {
        unsigned char ip[16]; // For IPv6
        unsigned short port;

        // Check the address type
        if (packet[3] == 0x01) { // IP V4 address
            // Extract the destination IPv4 address from packet bytes 4 to 7
            ip[0] = packet[4];
            ip[1] = packet[5];
            ip[2] = packet[6];
            ip[3] = packet[7];
            // Extract the destination port from packet bytes 8 to 9
            port = (packet[8] << 8) | packet[9];
            // Print detected SOCKS5 connection details to the console
            printf("SOCKS5 connection found from %d.%d.%d.%d:%d\n", ip[0], ip[1], ip[2], ip[3], port);
        } else if (packet[3] == 0x03) { // DOMAINNAME
            int domainLength = packet[4]; // Get domain name length
            char domain[256]; // Assume a max domain name length of 255 (including NULL terminator)
            memset(domain, 0, sizeof(domain)); // Clear the domain buffer
            if (length < domainLength + 5) {
                return; // Not enough data for domain name
            }
            // Extract the domain name from packet bytes 5 onwards
            memcpy(domain, &packet[5], domainLength);
            // Extract the destination port from packet bytes after the domain name
            port = (packet[5 + domainLength] << 8) | packet[5 + domainLength + 1];
            // Print detected SOCKS5 connection details to the console
            printf("SOCKS5 connection found from %s:%d\n", domain, port);
        } else if (packet[3] == 0x04) { // IP V6 address
            // Extract the destination IPv6 address (not implemented in this example)
            return; // Not handling IPv6 in this example
        } else {
            return; // Unsupported address type
        }

        // Log the connection details to a file named socks5.log
        FILE *logFile = fopen("socks5.log", "a");
        if (logFile != NULL) {
            fprintf(logFile, "SOCKS5 connection found from (details here)\n");
            fclose(logFile);
        } else {
            printf("Error opening log file!\n");
        }
    }
}

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    inspectSOCKS5(packet, pkthdr->caplen);
}

int main() {
    // Daemonizing the process to run as a background service
    pid_t pid, sid;

    pid = fork();
    if (pid < 0) {
        exit(EXIT_FAILURE);
    }

    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    umask(0);
    sid = setsid();
    if (sid < 0) {
        exit(EXIT_FAILURE);
    }

    if ((chdir("/")) < 0) {
        exit(EXIT_FAILURE);
    }

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    // Start the packet capture loop
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
