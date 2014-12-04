
#include "ps_scan.hpp"
#include "ps_netw.hpp"

// standard libraries
#include <cstdio>
#include <cstdlib>
#include <cstring>

// networking libraries
#include <netinet/tcp.h>	// tcp header
#include <netinet/ip.h>	// ip header
#include <netinet/udp.h>	// udp header
#include <ifaddrs.h>


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

	// get source machine's IP address
	getMachineIPaddr(this->machineIP);

	while ( !workQueue.empty() ) {	// until all jobs are done
		
		job_t job = workQueue.front();	// get next job

		if (job.scanType != "UDP") {	// for all scan type other than "UDP"
			packet = getTCPpacket( const_cast<char *>( (job.ipAddr).c_str() ), job.portNo, const_cast<char *>( (job.scanType).c_str() ), machineIP, SRC_PORT);
		} else if ( job.scanType == "UDP" && job.portNo == 53 ) {	// for a DNS query

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
    	freeifaddrs(addrStruct);
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

	char datagram[4096];	// buffer representing packet
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
	/*ipHeader->saddr = 
	ipHeader->daddr = */	// TODO

	ipHeader->check = calcChecksum( (uint16_t *) datagram, sizeof(struct ip) );	// calculate actual checksum for ip header

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
