#include	<stdio.h>
#include	<string.h>
#include	<time.h>
#include	<net/ethernet.h>
#include	<netinet/ether.h>
#include	<arpa/inet.h>
#include	<pcap.h>

typedef struct _IpPairCount{
	int saddr;
	int daddr;
	int count;
}IpPairCount;

int main(int argc, char* argv[]){
	char errbuf[PCAP_ERRBUF_SIZE];

	if(argc != 3 || strcmp(argv[1], "-r") != 0){
		fprintf(stderr, "Usage: pcap_read -r FILENAME\n");
		return -1;
	}

	pcap_t* handle = pcap_open_offline(argv[2], errbuf);
	if(handle == NULL){
		fprintf(stderr, "%s\n", errbuf);
		return -1;
	}

	IpPairCount pairs[1024];
	int count;

	while(1){
		struct pcap_pkthdr* header = NULL;
		const u_char* packet = NULL;
		int res = pcap_next_ex(handle, &header, &packet);
		if(res == PCAP_ERROR_BREAK)
			break;
		else if(res == 1){
			struct timeval* tv = &(header->ts);
			struct tm* tm = localtime(&(tv->tv_sec));
			char timeStr[64];
			strftime(timeStr, 64, "%F %T", tm);
			printf("Time: %s, Captured packet length: %d, Total packet length: %d\n", timeStr, header->len, header->caplen);
			struct ether_header* packetHeader = (struct ether_header*)packet;
			struct ether_addr smac, dmac;
			memcpy(&smac, &(packetHeader->ether_shost), sizeof(struct ether_addr));
			memcpy(&dmac, &(packetHeader->ether_dhost), sizeof(struct ether_addr));
			printf("Source MAC address: %s, ", ether_ntoa(&smac));
			printf("Destination MAC address: %s\n", ether_ntoa(&dmac));
			if(ntohs(packetHeader->ether_type) == ETHERTYPE_IP){
				printf("Type: IP(Protocol: ");
				const u_char* proto = packet + 14 + 9;	// ethernet header length = 14, protocol number start at offset 9 bytes
				if(*proto == IPPROTO_TCP)
					printf("TCP)\n");
				else if(*proto == IPPROTO_UDP)
					printf("UDP)\n");
				else if(*proto == 89)
					printf("OSPF(Protocol 89))\n");
				else
					printf("Other)\n");

				/* get ip address */
				char ipAddrStr[64];
				int saddr, daddr;
				const u_char* ipAddrPtr = packet + 14 + 12;		// source ip address start at offset 12 bytes
				saddr = *((int*)ipAddrPtr);
				inet_ntop(AF_INET, ipAddrPtr, ipAddrStr, INET_ADDRSTRLEN);
				printf("Source IP address: %s, ", ipAddrStr);
				ipAddrPtr += 4;		// dest ip address is next to source ip address
				daddr = *((int*)ipAddrPtr);
				inet_ntop(AF_INET, ipAddrPtr, ipAddrStr, INET_ADDRSTRLEN);
				printf("Destination IP address: %s\n", ipAddrStr);

				/* add to pairs */
				int i;
				for(i = 0; i < count; i++){
					if(saddr == pairs[i].saddr && daddr == pairs[i].daddr){
						(pairs[i].count)++;
						break;
					}
				}
				if(i == count){
					pairs[count].saddr = saddr;
					pairs[count].daddr = daddr;
					pairs[count].count = 1;
					count++;
				}

				if(*proto == IPPROTO_TCP || *proto == IPPROTO_UDP){
					/* get port number */
					int ipHeaderLen = *(packet + 14) & 0x0F;	// first byte of ip header is version(4 bits) + header length(4 bits), so we only get the length value
					ipHeaderLen *= 4;		// the length's unit is word(32 ibts), so we convert to bytes
					printf("Source port Number: %d, ", ntohs(*((short*)(packet + 14 + ipHeaderLen))));		// port number is 16-bits wide, so we cast the pointer to a short pointer
					printf("Destination port Number: %d\n", ntohs(*((short*)(packet + 14 + ipHeaderLen + 2))));		// dest port number is next to source port number
				}
			}
			else if(ntohs(packetHeader->ether_type) == ETHERTYPE_ARP){
				printf("Type: ARP\n");
			}
			else
				printf("Type: Other\n");
		}
		else if(res == 0)
			printf("Timeout\n");
		else if(res == PCAP_ERROR)
			fprintf(stderr, "%s\n", pcap_geterr(handle));
		printf("---------------------------------------------------------------------------------------\n");
	}
	printf("Number of IP packets:\n");
	int i;
	for(i = 0; i < count; i++){
		char addrStr[64];
		inet_ntop(AF_INET, &(pairs[i].saddr), addrStr, INET_ADDRSTRLEN);
		printf("(%s -> ", addrStr);
		inet_ntop(AF_INET, &(pairs[i].daddr), addrStr, INET_ADDRSTRLEN);
		printf("%s)\t%d packets.\n", addrStr, pairs[i].count);
	}

	pcap_close(handle);

	return 0;
}
