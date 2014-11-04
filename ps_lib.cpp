
#include "ps_lib.h"

// standard libraries
#include <cstring>
#include <cstdlib>

/* default constructor for class ArgsParser */
ArgsParser::ArgsParser() {
	memset(this->filename, 0x00, sizeof(this->filename));	// null filename by default
}

/*
 * usage() -> void
 * displays instructions on how to run the program
 */
void ArgsParser::usage(FILE *file) {
 	if (file == NULL)
 		file = stdout;	// set standard output as file stream by default

 	fprintf(file, ".portScanner [OPTIONS] \n"
 					"	--help						\tPrint instructions on how to run portScanner\n"
 					"	--ports <ports to scan>				\tScan specified ports on IP address\n"
 					"	--ip <IP address to scan>			\tScan ports on specified IP address\n"
 					"	--prefix <IP prefix to scan>			\tScan a range of IP addresses\n"
 					"	--file <file name containing IP addresses to scan>\tRead specified file name that contains list of IP addresses to scan\n"
 					"	--speedup <parallel threads to use>		\tMulti-threaded version of portScanner; specifies number of threads to be used\n"
 					"	--scan <one or more scans>			\tType of scan to be performed\n"
			);
}

/*
 * parse_args() -> void
 * makes sense of each command line argument specified beside the program
 */
void ArgsParser::parse_args(int argc, char *argv[]) {
 	int g;	// to grab return value of getopt_long()
 	int longindex = 0;	// array index of struct longopts set by getopt_long()
 	while ( (g = getopt_long(argc, argv, "", longopts, &longindex)) != -1 ) {
 		switch(g) {
			case 'h':
				this->usage(stdout);
				exit(1);
			case 'p':
				this->getports(optarg);
				break;
			default:
				this->usage(stderr);
				break;
		}
 	}
}

/*
 * getports() -> void
 * makes note of each port specified at command line
 */
void ArgsParser::getports(char *str) {
	char *token;
	char delim[] = ",-";
}