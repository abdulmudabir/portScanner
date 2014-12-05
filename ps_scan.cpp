
#include "ps_scan.hpp"
#include "ps_netw.hpp"

// standard libraries
#include <cstdio>
#include <cstdlib>
#include <cstring>

// networking libraries
#include <netinet/ip.h>	// ip header
#include <netinet/udp.h>	// udp header
#include <ifaddrs.h>
#include <sys/socket.h>

void Scanner::initPktSniffing() {

	/** set up a default network device to capture packets **/
	char errbuf[PCAP_ERRBUF_SIZE];	// to fill error message
	char *netwdev = pcap_lookupdev(errbuf);	// returns a default network device
	if (netwdev == NULL) {
		fprintf(stderr, "\nError: Unable to find a default network device.\n");
		exit(1);
	}

	/** fetch IPv4 network number & netmask for network device **/
	bpf_u_int32 netwnum, netmask;
	if ( pcap_lookupnet(netwdev, &netwnum, &netmask, errbuf) == -1 ) {
		fprintf(stderr, "\nWarning: Unable to IP address and netmask for device.\n");
		netwnum = 0;	// unreachable IP
		netmask = 0;	// no netmask
	}

	/** open network device to sniff packets; get a handle to the capture **/
	this->snifferSession = pcap_open_live( netwdev, SNAP_LEN, NO_PROMISC, READ_TIMEOUT, errbuf);
	if (this->snifferSession == NULL) {
		fprintf(stderr, "\nError: Unable to open network device.\n");
		exit(1);
	}

	/** setup a filter for sniffing selected traffic **/
	char filter_exp[40];
	snprintf(filter_exp, sizeof filter_exp, "dst port %d or ip proto \\icmp", SRC_PORT);

	/** need to setup a packet filter program with filter expression **/
	struct bpf_program fp;
	if (pcap_compile(this->snifferSession, &fp, filter_exp, 0, netmask) == -1) {
		fprintf( stderr, "\nError: Unable to setup packet filter program, error message: %s\n ", pcap_geterr(this->snifferSession) );
		exit(1);
	}

	/** finally, set the packet filter **/
	if ( pcap_setfilter(this->snifferSession, &fp) == -1) {
		fprintf( stderr, "\nError: Unable to setup packet filter, error message: %s\n ", pcap_geterr(this->snifferSession) );
		exit(1);
	}

}

void Scanner::runJobs() {

	cout << endl;	// new line
	
	char *packet = NULL;	// packet to be sent to dst port
	int packetLen;	// length of packet

	// get source machine's IP address
	getMachineIPaddr(this->machineIP);

	int sockfd;	// socket handle, set according to type of scan

	while ( !workQueue.empty() ) {	// until all jobs are done
		
		job_t job = workQueue.front();	// get next job

		if ( strcasecmp( (job.scanType).c_str(), "UDP") != 0 ) {	// for all scan types other than "UDP"; strcasecmp() used instead of std::string::compare for case insensitivity

			/** make a packet with appropriate TCP flags set **/
			packet = getTCPpacket( const_cast<char *>( (job.ipAddr).c_str() ), job.portNo, const_cast<char *>( (job.scanType).c_str() ), machineIP, SRC_PORT );

			/** keep a Raw socket handy for TCP scans **/
			if ( (sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0 ) {
				fprintf(stderr, "Error: Unable to create raw socket.\n");
				exit(1);
			}
		
		} else if ( (strcasecmp( (job.scanType).c_str(), "UDP") == 0) && job.portNo == 53 ) {	// for a DNS query

			/** make a DNS query packet **/
			packet = getDNSQueryPacket( (unsigned char *) "stackoverflow.com", 	// domain name for DNS query
										A_RECORD, 	// Address record type DNS query
										packetLen 	// to get length of packet
										);

		} else {	// all other standard "UDP" scan types other than DNS query type

		}

		workQueue.pop();	// move on to next job

	}
}

void Scanner::getMachineIPaddr(char *hostip) {

	memset(hostip, 0x00, INET_ADDRSTRLEN);	// zero-out ip addr holder initially

	struct ifaddrs *addrStruct = NULL;	// store linked list of network interfaces of local system
	struct ifaddrs *ifa = NULL;	// to iterate over interface linked list

	getifaddrs(&addrStruct);	// creates linked list

	for (ifa = addrStruct; ifa != NULL; ifa = ifa->ifa_next) {
        if ( ifa->ifa_addr->sa_family == AF_INET ) {	// concerned with IPv4 address

        	if ( strcmp(ifa->ifa_name, "eth0") == 0 ) {	// for network interface type: ethernet
        		struct in_addr addr = ( (struct sockaddr_in *) ifa->ifa_addr )->sin_addr;
        		snprintf( hostip, INET_ADDRSTRLEN, "%s", inet_ntoa(addr) );
        	}
        }
    }

    if ( addrStruct != NULL ) {
    	freeifaddrs(addrStruct);	// free interface addresses
    }

    if ( strlen(hostip) == 0 ) {	// if IP not populated
    	fprintf(stderr, "\nError: Could not determine local machine's IP.\n");
    	exit(1);
    }

}

char * Scanner::getTCPpacket(char *dstIP, int dstPort, char *scanname, char *srcIP, int srcPort) {

	/** refer IP, TCP headers **/
	struct iphdr *ipHeader = NULL;
	struct tcphdr *tcpHeader = NULL;

	static char datagram[4096];	// buffer representing packet
	memset(datagram, 0x00, sizeof datagram);	// zero-out buffer initially

	/** consruct IP header part of packet **/
	ipHeader = (struct iphdr *) datagram;
	ipHeader->ihl = 5;	// internet header length; number of 32-bit words in header
	ipHeader->version = 4;	// IPv4
	ipHeader->tos = 0;	// type of service; 0 as standard, some other service like VoIP may require setting this field
	ipHeader->tot_len = sizeof(struct ip) + sizeof(struct tcphdr);	// total length of ip header; (struct ip) guarantees IP header without options
	ipHeader->id = htons(9876);	// set some simple identification
	ipHeader->frag_off = 0;	// no fragmentation
	ipHeader->ttl = 64;	// seconds, can also be seen as hop counts (decrements by 1); standard seen as 64 usually (e.g. ping program)
	ipHeader->protocol = IPPROTO_TCP;	// value 6 for TCP protocol
	ipHeader->check = 0;	// set to 0 before checksum calculation
	ipHeader->saddr = inet_addr(srcIP);	// source address as an integer (32-bit)
	ipHeader->daddr = inet_addr(dstIP);	// destination address as an integer (32-bit)

	ipHeader->check = calcChecksum( (uint16_t *) datagram, sizeof(struct ip) );	// calculate actual checksum for ip header; pass ptr ipHeader if you need to

	/** consruct TCP header part of packet **/
	tcpHeader = (struct tcphdr *) ( datagram + sizeof(struct ip) );
	tcpHeader->source = htons(srcPort);	// source port
	tcpHeader->dest = htons(dstPort);	// destination port
	tcpHeader->seq = htonl(100000);	// sequence number; for identification of packet
	tcpHeader->ack_seq = 0;	// acknowledgment number
	tcpHeader->doff = (sizeof(struct tcphdr) / 4);	// specifies size of tcphdr in 32-bit words
	tcpHeader->fin = 0;	// set all flags to 0 prior to sending packet
	tcpHeader->syn = 0;
	tcpHeader->rst = 0;
	tcpHeader->psh = 0;
	tcpHeader->ack = 0;
	tcpHeader->urg = 0;
	tcpHeader->window = htons(14600);	// size of receive window; max 65535 bytes; optimal usually: bandwidth * latency (bytes)
	tcpHeader->check = 0;	// set to 0 before checksum calculation
	tcpHeader->urg_ptr = 0;	// urgent pointer

	/** set tcp header flags according to scan type on record **/
	const char *allscans[6] = { "SYN", "NULL", "FIN", "XMAS", "ACK", "UDP" };
	int i;

	for (i = 0; i < 6; i++) {	// like assigning integer to each scan type
		if ( strcasecmp(scanname, allscans[i]) == 0 ) {	// ignore case when comparing strings
			break;
		}
	}

	switch (i) {
		case 0:	// SYN scan
			tcpHeader->syn = 1;
			break;
		case 1:	// NULL scan
			break;	// no flags to set
		case 2:	// FIN scan
			tcpHeader->fin = 1;
			break;
		case 3:	// XMAS scan
			tcpHeader->fin = 1;
			tcpHeader->psh = 1;
			tcpHeader->urg = 1;
			break;
		case 4:	// ACK scan
			tcpHeader->ack = 1;
			break;
		default:	// scan type cannot be "UDP" here
			break;
	}

	/** TCP header checksum needs to be calculated along with a pseudo header **/
	struct pseudohdr *soodohdr = NULL;
	soodohdr->src = inet_addr(srcIP);	// integer form of source IP address
	soodohdr->dst = inet_addr(dstIP);	// integer form of destination IP address
	soodohdr->mbz = 0;	// 8 reserved bits, all set to 0
	soodohdr->protocol = IPPROTO_TCP;	// TCP protocol
	soodohdr->tcp_len = htons( sizeof(struct tcphdr) );
	memcpy( &soodohdr->hdrtcp, tcpHeader, sizeof(struct tcphdr) );	// tcp header field of pseudo header

	/** calculate tcp header checksum now that we have our pseudo header **/
	tcpHeader->check = calcChecksum( (uint16_t *) soodohdr, sizeof(struct pseudohdr) );

	return datagram;	// serve packet
	
}

uint16_t Scanner::calcChecksum( uint16_t *pktref, int hdrlen) {
	
	uint32_t sum = 0;	// store final sum here; 0 initially; let this be 32-bit for carry over bits

	for (int i = 0; i < (hdrlen / 2); i++) {	// e.g. header length 20 / 2 = 10 16-bit portions to iterate
		sum += *pktref;	// keep adding current 16-bit header portion to last sum
		pktref++;	// increment to next 16-bit portion
	}

	/** just in case header length turned out odd **/
	if ( (hdrlen % 2) != 0 ) {
		pktref++;
		sum += *pktref;	// add the one-odd 16-bit header portion
	}

	/** add carry over bits to last sum **/
	sum = (sum & 0xffff) 	// only last 16-bits in checksum
					+ (sum >> 16);	// only carry over bits
	sum = sum + (sum >> 16);	// in case there was still that one last carry over bit

	return ((uint16_t) ~sum);	// 16-bit one's complement of 'sum'

}

char * Scanner::getDNSQueryPacket( unsigned char *domainName, int recordType, int &pktLength) {
	
	static char dnsbuf[4096];	// dns datagram buffer
	memset(dnsbuf, 0x00, sizeof dnsbuf);	// zero-out buffer initially

	/** make dns header in packet **/
	struct dnshdr *dnsHeader = (struct dnshdr *) dnsbuf;	// get reference to dns header
	dnsHeader->id = htons(123);	// set identification number
	dnsHeader->qr = 0;	// is a query
	dnsHeader->opcode = 0;	// set 0 for a standard query
	dnsHeader->aa = 0;	// non-authoritative answer
	dnsHeader->tc = 0;	// no truncation
	dnsHeader->rd = 1;	// recursively query for answer
	dnsHeader->ra = 0;	// recursive query support not available
	dnsHeader->z = 0;
	dnsHeader->rcode = 0;	// response code not set
	dnsHeader->qdcount = 1;	// 1 question
	dnsHeader->ancount = 0;	// no answers
	dnsHeader->nscount = 0;	// no nameservers
	dnsHeader->arcount = 0;	// no additional records

	/** make dns question portion in packet **/
	unsigned char *qname = (unsigned char *) ( dnsbuf + sizeof(struct dnshdr) );	// get reference to location after dns header to append domain name details
	sprintf( (char *) qname, "%s", domainName);	// fill domain name to mark start of dns question portion of packet
	struct dnsquery *dnsQ = (struct dnsquery *) ( dnsbuf + sizeof(struct dnshdr) + (strlen( (const char *) qname ) + 1) );	// reference to location after dns header and question name
	dnsQ->qtype = htons(recordType);	// query type A
	dnsQ->qclass = htons(1);	// represents Internet address

	/** get length of entire DNS query packet **/
	pktLength = sizeof(struct dnshdr) + strlen( (const char *) qname ) + 1 + sizeof(struct dnsquery);

	return dnsbuf;	// serve packet

}