
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
extern vector<int>::iterator vect_itr;	// an iterator for ports 'vector'
extern vector<string> hosts_vect;	// to store IP addresses of hosts specified at cli

#endif

class ArgsParser {
	private:
		char filename[50];	// to store file name containing IP addresses
	public:
		ArgsParser();
		void usage(FILE *);
		void parse_args(int, char**);
		void getports(char *);
		void gethosts(char *);
		void parse_prefixes(char *);
};

static struct option longopts[]  = {
	{"help", 	no_argument, 		0, 	'h'},
	{"ports", 	required_argument, 	0, 	'p'},
	{"ip", 		required_argument, 	0, 	'i'},
	{"prefix", 	required_argument, 	0, 	'x'},
	{"file", 	required_argument, 	0, 	'f'},
	{"speedup", required_argument, 	0, 	'u'},
	{"scan", 	required_argument, 	0, 	's'},
	{0, 0, 0, 0}
};

#endif