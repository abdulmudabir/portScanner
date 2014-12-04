
#ifndef _PS_SCAN_HPP_
#define _PS_SCAN_HPP_

// standard libraries
#include <pcap/pcap.h>

// macros
#define TIMEOUT 4
#define SNAP_LEN 1518	// max number of bytes for every packet being sniffed
#define NO_PROMISC 0	// non promiscuous mode; do not sniff all traffic
#define READ_TIMEOUT 0	// timeout in milliseconds needed for certain platforms
#define SRC_PORT 2015	// set unoccupied, unofficial source port randomly

class Scanner {
	private:
		pcap_t *snifferSession;	// handle to packet capture session
	public:
		void initPktSniffing();
};

#endif