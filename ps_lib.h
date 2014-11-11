
#ifndef _PS_LIB_H_
#define _PS_LIB_H_

// standard libraries
#include <cstdio>
#include <string>
#include <getopt.h>
#include <sys/types.h>

// networking libraries
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

// STL containers
#include <set>

using namespace std;

#ifndef vars
#define vars

extern set<int> ports_set;	// to store ports that need to be scanned
extern set<int>::iterator intvect_set;	// an iterator for ports 'vector'
extern set<string> ips_set;	// to store IP addresses of hosts specified at cli
extern set<string> reservedIPs_set;	// a record of all IETF & IANA specified reserved IP addresses
extern set<string>::iterator strset_itr;	// an iterator for IP containing 'vector'
extern set<string> scans_set;	// to store port scan types specified by user

#endif

class ArgsParser {
	private:
		char filename[50];	// to store file name containing IP addresses
		int num_threads;	// to store number of threads to run in the multi-threaded version of program
	public:
		ArgsParser();
		void usage(FILE *);
		// void fill_resv_IPs();
		void parse_args(int, char**);
		void getports(char *);
		void getIP(char *);
		void checkIP(char *);
		void parse_prefixes(char *, set<string> &);
		void readIPfile(char *);
		uint32_t convert_endianness(uint32_t);
		uint32_t powerof2(int);
		void print_setelems(set<int> &);
		void print_setelems(set<string> &);
		int get_threads();
		void parse_scans(int, char **);

};

static struct option longopts[]  = {
	{"help", 	no_argument, 		0, 	'h'},
	{"ports", 	required_argument, 	0, 	'p'},
	{"ip", 		required_argument, 	0, 	'i'},
	{"prefix", 	required_argument, 	0, 	'x'},
	{"file", 	required_argument, 	0, 	'f'},
	{"speedup", required_argument, 	0, 	't'},
	{"scan", 	required_argument, 	0, 	's'},
	{0, 0, 0, 0}
};

#endif