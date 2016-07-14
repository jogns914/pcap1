pcap:
	gcc -o pcap pcap.c -lpcap -I/usr/include/pcap
clean:
	rm -f pcap
