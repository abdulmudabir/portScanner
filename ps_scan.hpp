
#ifndef _PS_SCAN_HPP_
#define _PS_SCAN_HPP_


// networking libraries
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>	// tcp header

// macros
#define TIMEOUT 4	// 4 seconds allowed for host to respond
#define SNAP_LEN 1518	// max number of bytes for every packet being sniffed
#define NO_PROMISC 0	// non promiscuous mode; do not sniff all traffic
#define READ_TIMEOUT 0	// timeout in milliseconds needed for certain platforms
#define SRC_PORT 2015	// set unoccupied, unofficial source port randomly

#define A_RECORD 1 	// DNS record type: A, for Address record

/* 
 * pseudo header type used for checksum calculation instead of struct tcphdr alone
 * 	look in Scanner::getTCPpacket() for details about this header's fields
 */
struct pseudohdr {
	uint32_t src;
	uint32_t dst;
	unsigned char mbz;
	unsigned char protocol;
	uint16_t tcp_len;

	struct tcphdr hdrtcp;	// includes a tcp header too
};

struct dnshdr {
	uint16_t id;	// identification
	unsigned char qr:1;	// whether query (0) or response (1)
	unsigned char opcode:4;	// indicates the kind of query
	unsigned char aa:1;	// authoritative answer
	unsigned char tc:1;	// truncation flag
	unsigned char rd:1;	// whether recursion desired
	unsigned char ra:1;	// whether recursive query support is available
	unsigned char z:1;	// reserved
	unsigned char rcode:4;	// response code set as part of responses

	uint16_t qdcount;	// specifies number of entries in the question section
	uint16_t ancount;	// specifies number of resource records in the answer section
	uint16_t nscount;	// specifies number of nameserver resource records in authority records section
	uint16_t arcount;	// specifies number of resource records in the additional records section
};

struct dnsquery {	// question name or domain name part is added separately to packet
	uint16_t qtype;	// type of the query e.g. A record, MX record, etc.
	uint16_t qclass;	// class of the query
};

class Scanner {
	private:
		pcap_t *snifferSession;	// handle to packet capture session
		char machineIP[INET_ADDRSTRLEN];	// local machine's IP address
	public:
		void initPktSniffing();
		void runJobs();
		void getMachineIPaddr(char *);
		char * getTCPpacket(char *, int, char *, char *, int);
		uint16_t calcChecksum( uint16_t *, int);
		char * getDNSQueryPacket( unsigned char *, int, int &);
};


#endif