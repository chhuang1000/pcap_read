all: pcap_read
pcap_read: main.c
	gcc -o pcap_read main.c -lpcap
