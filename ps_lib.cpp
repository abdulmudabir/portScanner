
/*
 * References:
 * 	http://linux.die.net/man/3/inet_aton	// convert IP to binary; reverse endianness
 * 	http://stackoverflow.com/questions/2182002/convert-big-endian-to-little-endian-in-c-without-using-provided-func
 * 	http://en.wikipedia.org/wiki/Reserved_IP_addresses	// reserved IP addresses
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
vector<string> reservedIPs_vect;
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

	this->checkIP(ip);	// first, check if valid IP address

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

/* checks for
 ** valid IP address format (xxx.xxx.xxx.xxx)
 ** IETF and IANA-specified "valid unreserved IP addresses" as stated at
 *** 	http://en.wikipedia.org/wiki/Reserved_IP_addresses
 */
void ArgsParser::checkIP(char *ip) {

	// CHECK FOR VALID IP ADDRESS FORMAT FIRST E.G. IGNORE IP ADDRESS: "18" OR "12.172", ETC.
	char *token;
	char delim[] = ".";
	int count;

	for ( count = 0, token = strtok(ip, delim); (count < 4 && token != NULL); (token = strtok(NULL, delim)), count++ ) {
		continue;
	}

	if (count != 4) {	// all cases other than (count = 4) imply invalid IP address format
		fprintf(stderr, "Error: Invalid IP address format. Good IP example: 129.79.247.1\n");
		this->usage(stderr);
		exit(1);
	} else {	// once IP format OK, check with reserved IPs list

		vector<string> resvIP_prefixes;	// reserved IPv4 addresses container

		// following set of reserved IP prefixes is as per the wiki link, add each to reserved list
		resvIP_prefixes.push_back("0.0.0.0/8");
		resvIP_prefixes.push_back("10.0.0.0/8");
		resvIP_prefixes.push_back("100.64.0.0/10");
		resvIP_prefixes.push_back("127.0.0.0/8");
		resvIP_prefixes.push_back("169.254.0.0/16");
		resvIP_prefixes.push_back("172.16.0.0/12");
		resvIP_prefixes.push_back("192.0.0.0/29");
		resvIP_prefixes.push_back("192.0.2.0/24");
		resvIP_prefixes.push_back("192.88.99.0/24");
		resvIP_prefixes.push_back("192.168.0.0/16");
		resvIP_prefixes.push_back("198.18.0.0/15");
		resvIP_prefixes.push_back("198.51.100.0/24");
		resvIP_prefixes.push_back("203.0.113.0/24");
		resvIP_prefixes.push_back("224.0.0.0/4");
		resvIP_prefixes.push_back("240.0.0.0/4");
		resvIP_prefixes.push_back("255.255.255.255/32");

		for ( strvect_itr = resvIP_prefixes.begin(); strvect_itr != resvIP_prefixes.end(); strvect_itr++ ) {
			this->fill_reservedIPs(*strvect_itr);
		}
		
	}

}

void ArgsParser::fill_reservedIPs(string str) {

	// copy "string IP prefix" into a new variable; keep original string untouched coz strtok() misbehaves
	string str_cpy(str);

	char prefix[strlen(str_cpy.c_str()) + 1];
	snprintf( prefix, (strlen(str_cpy.c_str()) + 1), "%s", str_cpy.c_str() );


	/*char prefix_cpy[strlen(prefix) + 1];
	snprintf(prefix_cpy, sizeof prefix_cpy, "%s", prefix);

	char *token;	// to tokenize IP prefix by separating forward-slash
	char delim[] = "/";
	char *netw_addr = new char[INET_ADDRSTRLEN + 1];	// allocate memory to hold IP
	char *lead_bits = new char[3];	// decimal after "/" in IP prefix cannot be more than 2 digits + 1 for null-terminator
	int i = 0;

	// separate IP from trailing bits part
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
	}*/

}

void ArgsParser::parse_prefixes(char *prefix, vector<string> &vec) {
	
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

	this->checkIP(netw_addr);	// first, check if valid IP address before proceeding

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