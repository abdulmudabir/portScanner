
#ifndef _PS_LIB_H_
#define _PS_LIB_H_

// standard libraries
#include <cstdio>
#include <getopt.h>
#include <sys/types.h>

// networking libraries
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

// STL containers
#include <vector>

using namespace std;

class ArgsParser {
	private:
		char filename[50];	// to store file name containing IP addresses
	public:
		ArgsParser();
		void usage(FILE *);
		void parse_args(int, char**);
		void getports(char *);
		void gethosts(char *);
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