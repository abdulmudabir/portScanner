
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
};


#endif