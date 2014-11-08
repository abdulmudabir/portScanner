
/*
 * References:
 * 	http://linux.die.net/man/3/inet_aton	// convert IP to binary; reverse endianness
 * 	http://stackoverflow.com/questions/2182002/convert-big-endian-to-little-endian-in-c-without-using-provided-func
 */

#include "ps_lib.h"

// standard libraries
#include <iostream>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <limits.h>
#include <cmath>

/* recall all global variables */
vector<int> ports_vect;
vector<int>::iterator intvect_itr;
vector<string> ips_vect;
vector<string>::iterator strvect_itr;

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
 					"	--prefix <IP prefix to scan>			\tScan a range of IP addresses. Eg. $ ./portScanner --prefix 127.0.0.1/24\n"
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
			case 'i':
				this->getIP(optarg);
				break;
			case 'x':
				this->parse_prefixes(optarg);
				break;
			default:
				this->usage(stderr);
				exit(1);
		}
 	}
}

/*
 * getports() -> void
 * makes note of each port specified at command line
 */
void ArgsParser::getports(char *str) {
	char delim[] = ",";	// tokenize char array on ","
	char *token;	// token holder

	for ( (token = strtok(str, delim)); token; token = strtok(NULL, delim) ) {	// tokenize until all tokens are retrieved
		string token_str(token);	// convert to type: string
		size_t dash_pos;	// holds index of the "-" if it is present in a token
		if ( ( dash_pos = token_str.find("-") ) != string::npos ) {	// check if "-" is present in token
			string port1_str(token_str.substr(0, dash_pos));	// string containing number upto "-"
			int start_port = atoi(port1_str.c_str());	// convert to integer
			string port2_str(token_str.substr(dash_pos + 1));	// string containing number following the "-"
			int end_port = atoi(port2_str.c_str());

			for (int i = start_port; i <= end_port; i++)	// fill ports vector with all ports from the start to end of the ports range
				ports_vect.push_back(i);
			
		} else {
			ports_vect.push_back(atoi(token));
		}
	}
}

void ArgsParser::getIP(char *ip) {
	struct hostent *hostinfo;	// hostent struct contains information like IP address, host name, etc.

	if ( (hostinfo = gethostbyname(ip)) == NULL) {
		fprintf(stderr, "Error: Host not found !\n");
		exit(1);
	}

	struct sockaddr_in hostip;	// to store IP address data structure
	hostip.sin_family = AF_INET;	// set Internet Addressing as IP family type
	memcpy( (char *) &hostip.sin_addr.s_addr, (char *) hostinfo->h_addr_list[0], strlen((char *) hostinfo->h_addr_list) );	// register IP address of host specified at cli
	
	string ip_holder(inet_ntoa(hostip.sin_addr));	// convert IP char array to string

	ips_vect.push_back(ip_holder);	// add to IP kitty

}

void ArgsParser::parse_prefixes(char *prefix) {
	
	// copy "prefix" into a new variable; keep "prefix" untouched coz strtok() misbehaves
	char prefix_cpy[strlen(prefix) + 1];
	snprintf(prefix_cpy, sizeof prefix_cpy, "%s", prefix);

	char *token;	// to tokenize IP prefix by separating forward-slash
	char delim[] = "/";
	char *netw_addr = new char[INET_ADDRSTRLEN + 1];	// allocate memory to hold IP
	char *lead_bits = new char[3];	// decimal after "/" in IP prefix cannot be more than 2 digits + 1 for null-terminator
	int i = 0;

	/* separate IP from trailing bits part */
	for ( (token = strtok(prefix_cpy, delim)); (token != NULL && i < 2); (token = strtok(NULL, delim)), i++ ) {
		switch(i) {
			case 0:
				snprintf(netw_addr, (strlen(token) + 1), "%s", token);
				break;
			case 1:
				snprintf(lead_bits, (strlen(token) + 1), "%s", token);
				break;
			default:
				break;
		}
	}

	if (i != 2) {	// all cases other than "i = 2" should mean an error; terminate program
		fprintf(stderr, "Error: Something's not right with the IP prefix.\n");
		this->usage(stderr);
		exit(1);
	}

	// IP VALIDATION NEEDED HERE, BEFORE USING inet_aton()

	unsigned long uint_addr;	// to store network byte order long of string IP (long -> 4 bytes)
	if ( (i = inet_aton(netw_addr, (struct in_addr *) &uint_addr)) < 1 ) {	// convert IP to long in network byte order
		fprintf(stderr, "Error: Could not understand network address in IP prefix.\n");	// inet_aton() returns non-zero for SUCCESS
		this->usage(stderr);
		exit(1);
	}
	
	uint32_t rev_endn = this->convert_endianness( (uint32_t) uint_addr);	// reverse endianness

	// create netmask
	uint32_t netw_bits = atoi(lead_bits);	// convert string to integer
	int host_bits = (32 - netw_bits);	// 32-bit IPv4 address would have host_bits amount reserved to get host addresses
	uint32_t netmask = UINT_MAX << host_bits;	// UINT_MAX to pacify ISO C90 warning when using "4294967295"

	uint32_t masked_rev_endn = rev_endn & netmask;	// apply Netmask
	uint32_t revofmaskedrev_endn = this->convert_endianness(masked_rev_endn);	// reverse endianness again before using inet_ntoa() coz it will reverse it anyway
	
	// store netmasked reverse endianned IP as string
	char next_ip[20];
	memset(next_ip, 0x00, sizeof next_ip);	// zero-out IP holder initially
	sprintf( next_ip, "%s", inet_ntoa( *(struct in_addr *) &revofmaskedrev_endn ) );

	ips_vect.push_back( (string) next_ip );	// push first IP in range to IP kitty

	/* push all successively generated IP addresses in specified range to vector */
	uint32_t loopvar = 1;
	uint32_t orred;
	uint32_t revorred;
	while ( loopvar < (uint32_t) this->powerof2(host_bits) ) {	// loop until all end of IP range where all host bits are set

		orred = masked_rev_endn | loopvar;	// generate next binary
		revorred = convert_endianness(orred);	// reverse endianness before inet_ntoa()
		memset(next_ip, 0x00, sizeof next_ip);	// flush buffer
		sprintf( next_ip, "%s", inet_ntoa( *(struct in_addr *) &revorred ) );
		ips_vect.push_back( (string) next_ip );	// add to IP kitty

		loopvar++;
	}

	/* free allocated memory */
	delete[] netw_addr;
	delete[] lead_bits;

}

/* converts endianness of a number (specifically from little-endian to big-endian for x86 machines) */
inline uint32_t ArgsParser::convert_endianness(uint32_t n) {
	return ( (n << 24) | ( (n << 8) & 0xff0000 ) | ( (n >> 8) & 0xff00 ) | (n >> 24) );
}

/* returns 2 raised to (number passed as argument) */
inline uint32_t ArgsParser::powerof2(int n) {
	return ( pow(2.0, (double) n) );	// math function for a raised to b: pow(a, b)
}

/* prints all elements found in vector<int> container passed as argument */
void ArgsParser::print_vectelems(vector<int> &vect) {
	for ( intvect_itr = vect.begin(); intvect_itr != vect.end(); intvect_itr++)
		cout << *intvect_itr << endl;
}

/* overloaded print_vectelems() function for vector<string> */
void ArgsParser::print_vectelems(vector<string> &vect) {
	for ( strvect_itr = vect.begin(); strvect_itr != vect.end(); strvect_itr++)
		cout << *strvect_itr << endl;
}
