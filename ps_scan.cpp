
#include "ps_scan.hpp"
#include "ps_netw.hpp"

// standard libraries
#include <cstdio>
#include <cstdlib>

#include <arpa/inet.h>

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

	cout << endl;	// line feed

	while ( !workQueue.empty() ) {	// until all jobs are done
		
		job_t job = workQueue.front();	// get next job

		if (job.scanType != "UDP") {	// for all scan type other than "UDP"
			cout << "not UDP, port# " << job.portNo << endl;
		} else if ( job.scanType == "UDP" && job.portNo == 53 ) {	// for a DNS query
			cout << "UDP, port# " << job.portNo << endl;
		} else {	// all other standard "UDP" scan types other than DNS query type
			cout << "UDP, port# " << job.portNo << endl;
		}

		workQueue.pop();
		
	}
}