#include <stdio.h>
#include <pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

//패킷헤더 구조체
struct ether_addr
{
      	unsigned char ether_addr_octet[6];
};

struct ether_header
{
      	struct  ether_addr ether_dhost;
      	struct  ether_addr ether_shost;
      	unsigned short ether_type;
};

struct ip_header
{
     	unsigned char ip_header_len:4;
     	unsigned char ip_version:4;
     	unsigned char ip_tos;
     	unsigned short ip_total_length;
	unsigned short ip_id;
      	unsigned char ip_frag_offset:5;
      	unsigned char ip_more_fragment:1;
	unsigned char ip_dont_fragment:1;
	unsigned char ip_reserved_zero:1;
       	unsigned char ip_frag_offset1;
      	unsigned char ip_ttl;
       	unsigned char ip_protocol;
      	unsigned short ip_checksum;
      	struct in_addr ip_srcaddr;
      	struct in_addr ip_destaddr;
};

struct tcp_header
{
       	unsigned short source_port;
       	unsigned short dest_port;
       	unsigned int sequence;
     	unsigned int acknowledge;
      	unsigned char ns:1;
     	unsigned char reserved_part1:3;
    	unsigned char data_offset:4;
     	unsigned char fin:1;
      	unsigned char syn:1;
      	unsigned char rst:1;
      	unsigned char psh:1;
     	unsigned char ack:1;
      	unsigned char urg:1;
      	unsigned char ecn:1;
     	unsigned char cwr:1;
      	unsigned short window;
       	unsigned short checksum;
       	unsigned short urgent_pointer;
};
        
void packet_header(unsigned char *, const struct pcap_pkthdr *, const unsigned char *);

int main(int argc, char *argv[])
{
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pd;
        
	if(!(dev = pcap_lookupdev(errbuf)))
	{
		perror(errbuf);
		exit(1);
	}
        
	if((pd = pcap_open_live(dev, 1024, 1, 100, errbuf)) == NULL) 
	{
		perror(errbuf);
		exit(1);
	}
        
	if(pcap_loop(pd, -1, packet_header, 0) < 0) 
	{
		perror(pcap_geterr(pd));
		exit(1);
	}
        
	pcap_close(pd);
        return 0;
}

void packet_header(unsigned char *user, const struct pcap_pkthdr *h, const unsigned char *packet)
{
	struct  ether_header *eh;
	unsigned short ether_type;
	struct  ip_header *ih;
	struct  tcp_header *th;
	int offset=0;

	eh= (struct ether_header *)packet;
	ether_type=ntohs(eh->ether_type);
	packet=packet+14;         
        ih = (struct ip_header *)packet;

	if(ether_type!=0x0800)
	{
		printf("ehter type wrong\n");
		return 0;
	}
	printf("\n============ETHERNET HEADER==========\n");
        printf("Dst MAC Addr [%02x:%02x:%02x:%02x:%02x:%02x]\n", // 6 byte for dest
        eh->ether_dhost.ether_addr_octet[0],
        eh->ether_dhost.ether_addr_octet[1],
       	eh->ether_dhost.ether_addr_octet[2],
        eh->ether_dhost.ether_addr_octet[3],
        eh->ether_dhost.ether_addr_octet[4],
        eh->ether_dhost.ether_addr_octet[5]);
        printf("Src MAC Addr [%02x:%02x:%02x:%02x:%02x:%02x]\n", // 6 byte for src
        eh->ether_shost.ether_addr_octet[0],
        eh->ether_shost.ether_addr_octet[1],
        eh->ether_shost.ether_addr_octet[2],
        eh->ether_shost.ether_addr_octet[3],
        eh->ether_shost.ether_addr_octet[4],
        eh->ether_shost.ether_addr_octet[5]);

	printf("\n==============IP HEADER==============\n");
        if(ih->ip_protocol == 0x06)
        {
                printf("Protocol : TCP\n");
        }
	else
	{
		printf("Protocal : Not TCP\n");
		return 0;
	}
        printf("Src IP Addr : %s\n", inet_ntoa(ih->ip_srcaddr) );
        printf("Dst IP Addr : %s\n", inet_ntoa(ih->ip_destaddr) );
       
        offset = ih->ip_header_len*4;
	packet = packet +offset;

	//tcp
	th = (struct tcp_header *)packet;
	printf("\n==============TCP HEADER==============\n");
        printf("Src Port Num : %d\n", ntohs(th->source_port) );
        printf("Dest Port Num : %d\n", ntohs(th->dest_port) );
}
