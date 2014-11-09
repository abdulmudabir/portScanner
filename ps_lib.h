
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
#include <vector>

using namespace std;

#ifndef vars
#define vars

extern vector<int> ports_vect;	// to store ports that need to be scanned
extern vector<int>::iterator intvect_itr;	// an iterator for ports 'vector'
extern vector<string> ips_vect;	// to store IP addresses of hosts specified at cli
extern vector<string> reservedIPs_vect;	// a record of all IETF & IANA specified reserved IP addresses
extern vector<string>::iterator strvect_itr;	// an iterator for IP containing 'vector'

#endif

class ArgsParser {
	private:
		char filename[50];	// to store file name containing IP addresses
	public:
		ArgsParser();
		void usage(FILE *);
		// void fill_resv_IPs();
		void parse_args(int, char**);
		void getports(char *);
		void getIP(char *);
		void checkIP(char *);
		void parse_prefixes(char *, vector<string> &);
		uint32_t convert_endianness(uint32_t);
		uint32_t powerof2(int);
		void print_vectelems(vector<int> &);
		void print_vectelems(vector<string> &);
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