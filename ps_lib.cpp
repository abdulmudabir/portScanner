
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
#include <algorithm>
#include <fstream>

/* recall all global variables */
vector<int> ports_vect;
vector<int>::iterator intvect_itr;
vector<string> ips_vect;
vector<string> reservedIPs_vect;
vector<string>::iterator strvect_itr;

// int resv_IPcheck = 0;	// indicates whether or not IP address is checked with reserved IPs list on record
int portsflag = 0;	// indicates whether or not ports are specified at cli

/* default constructor for class ArgsParser */
ArgsParser::ArgsParser() {
	memset(this->filename, 0x00, sizeof(this->filename));	// null filename by default
	this->num_threads = 0;	// 0 by default to indicate no-multi-threading	
}

/*
 * usage() -> void
 * displays instructions on how to run the program
 */
void ArgsParser::usage(FILE *file) {
 	if (file == NULL)
 		file = stdout;	// set standard output as file stream by default

 	fprintf(file, "./portScanner [OPTIONS] \n"
 					"	--help						\tPrint instructions on how to run portScanner\n"
 					"	--ports <ports to scan>				\tScan specified ports on IP address Eg. $ ./portScanner --ports 1,10,90-100\n"
 					"	--ip <IP address to scan>			\tScan ports on specified IP address. Eg. $ ./portScanner --ip 129.79.247.87\n"
 					"	--prefix <IP prefix to scan>			\tScan a range of IP addresses. Eg. $ ./portScanner --prefix 127.0.0.1/24\n"
 					"	--file <file name containing IP addresses to scan>\tRead specified file name that contains list of IP addresses to scan. Eg. $ ./portScanner --file ipaddresses.txt\n"
 					"	--speedup <parallel threads to use>		\tMulti-threaded version of portScanner; specifies number of threads to be used. Rounds down floating point numbers. Eg. $ ./portScanner --speedup 5\n"
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
				portsflag = 1;	// indicate "--ports " was specified at cli
				this->getports(optarg);
				break;
			case 'i':
				this->getIP(optarg);
				break;
			case 'x':
				this->parse_prefixes(optarg, ips_vect);
				break;
			case 'f':
				this->readIPfile(optarg);
				break;
			case 't':
				this->num_threads = atoi(optarg);
				if (num_threads <= 0) {
					fprintf(stderr, "Error: Invalid number of threads specified.\n");
					this->usage(stderr);
					exit(1);
				}
				break;
			default:
				this->usage(stderr);
				exit(1);
		}
 	}

 	if (portsflag == 0) {	// "--ports " were not specified, use default ports 1-1024
 		for (int i = 1; i <= 1024; i++ ) {
 			ports_vect.push_back(i);
 		}
 	}
}

/*// make a list of all reserved IP addresses that user cannot use to port scan
void ArgsParser::fill_resv_IPs() {

	resv_IPcheck = 1;	// set flag to indicate reserved IP address is to follow

	// following set of reserved IP prefixes is as per the wiki link
	char *resv[16] = { "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", 
		"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/29", "192.0.2.0/24", 
		"192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", 
		"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32" };

	for (int i = 0; i < 16; i++) {
		parse_prefixes(const_char<char *>(resv[i]), reservedIPs_vect);	// fill each reserved IP range into reserved IPs list
	}

}*/

/*
 * getports() -> void
 * makes note of each port specified at command line
 */
void ArgsParser::getports(char *str) {
	char delim[] = ",";	// tokenize char array on ","
	char *token;	// token holder

	// make a copy of original string argument
	char str_cpy[strlen(str) + 1];
	snprintf(str_cpy, (strlen(str) + 1), "%s", str);

	for ( (token = strtok(str_cpy, delim)); token; token = strtok(NULL, delim) ) {	// tokenize until all tokens are retrieved
		string token_str(token);	// convert to type: string
		size_t dash_pos;	// holds index of the "-" if it is present in a token
		if ( ( dash_pos = token_str.find("-") ) != string::npos ) {	// check if "-" is present in token
			
			string port1_str(token_str.substr(0, dash_pos));	// string containing number upto "-"
			
			if (port1_str.empty()) {	// case when a negative port number was specified; REJECT such negative port numbers
				fprintf(stderr, "Error: Negative port numbers are invalid.\n");
				this->usage(stderr);
				exit(1);
			}

			int start_port = atoi(port1_str.c_str());	// convert to integer

			string port2_str(token_str.substr(dash_pos + 1));	// string containing number following the "-"

			int p;
			if ( ( p = atoi(port2_str.c_str()) ) < 0 ) {
				fprintf(stderr, "Error: Negative port numbers are invalid.\n");
				this->usage(stderr);
				exit(1);
			}

			int end_port = atoi(port2_str.c_str());

			for (int i = start_port; i <= end_port; i++)	// fill ports vector with all ports from the start to end of the ports range
				ports_vect.push_back(i);
			
		} else {
			ports_vect.push_back(atoi(token));
		}
	}
}

/* parses IP address specified with "--ip" option, checks its validity */
void ArgsParser::getIP(char *ip) {
	struct hostent *hostinfo;	// hostent struct contains information like IP address, host name, etc.

	this->checkIP(ip);	// first, check if valid IP address

	if ( (hostinfo = gethostbyname(ip)) == NULL) {	// this check takes care of invalid input like negative IP addr octets too, weird characters in octets, among others
		fprintf(stderr, "Error: Something's not right with the IP address/es.\n");
		this->usage(stderr);
		exit(1);
	}

	struct sockaddr_in hostip;	// to store IP address data structure
	hostip.sin_family = AF_INET;	// set Internet Addressing as IP family type
	memcpy( (char *) &hostip.sin_addr.s_addr, (char *) hostinfo->h_addr_list[0], strlen((char *) hostinfo->h_addr_list) );	// register IP address of host specified at cli
	
	string ip_holder(inet_ntoa(hostip.sin_addr));	// convert IP char array to string

	ips_vect.push_back(ip_holder);	// add to IP kitty

}

/* checks if
 ** IPv4 address is in valid format (xxx.xxx.xxx.xxx)
 ** IP address is not an IETF and IANA-specified reserved IP addresses as stated at
 *** 	http://en.wikipedia.org/wiki/Reserved_IP_addresses
 */
void ArgsParser::checkIP(char *ip) {

	// CHECK FOR VALID IP ADDRESS FORMAT FIRST E.G. IGNORE IP ADDRESS: "18" OR "12.172", ETC.
	char *token;
	char delim[] = ".";
	int count;

	// copy IP to keep it safely untouched
	char ip_cpy[strlen(ip) + 1];
	snprintf(ip_cpy, sizeof ip_cpy, "%s", ip);

	for ( count = 0, token = strtok(ip_cpy, delim); (count < 4 && token != NULL); (token = strtok(NULL, delim)), count++ ) {
		continue;
	}

	if (count != 4) {	// all cases other than (count = 4) imply invalid IP address format
		fprintf(stderr, "Error: Invalid IP address format. Good IP example: 129.79.247.1\n");
		this->usage(stderr);
		exit(1);
	} 

/*	// once IP format OK, check IP with reserved IPs list
	if ( ( strvect_itr = find(reservedIPs_vect.begin(), reservedIPs_vect.end(), (string) ip_cpy) ) != reservedIPs_vect.end()) {	// IP found in reserved IPs list
		fprintf(stderr, "Error: A known reserved IP address is not allowed.\n"
			"More details on reserved IPs: http://en.wikipedia.org/wiki/Reserved_IP_addresses\n");
		usage(stderr);
		exit(1);
	}	// else all OK*/

}

void ArgsParser::parse_prefixes(char *prefix, vector<string> &vect) {
	
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

	/*// if this is reserved IP addresses prefix parsing, bypass the IP check
	if (resv_IPcheck != 1) {
		this->checkIP(netw_addr);
	}*/

	this->checkIP(netw_addr);	// validate IP

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

	vect.push_back( (string) next_ip );	// push first IP in range to IP kitty

	/* push all successively generated IP addresses in specified range to vector */
	uint32_t loopvar = 1;
	uint32_t orred;
	uint32_t revorred;
	while ( loopvar < (uint32_t) this->powerof2(host_bits) ) {	// loop until all end of IP range where all host bits are set

		orred = masked_rev_endn | loopvar;	// generate next binary
		revorred = convert_endianness(orred);	// reverse endianness before inet_ntoa()
		memset(next_ip, 0x00, sizeof next_ip);	// flush buffer
		sprintf( next_ip, "%s", inet_ntoa( *(struct in_addr *) &revorred ) );
		vect.push_back( (string) next_ip );	// add to IP kitty

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

/* reads and stores the set of IPs/IP prefixes contained in a text file */
void ArgsParser::readIPfile(char *file) {
	ifstream fin;	// input file stream
	fin.open(file);	// open file
	string lof;	// to grab each line from file
	size_t slashpos;	// to grab position of "/" in IP if any

	if (fin.is_open()) {	// checks if input stream is well associated with file
		while (fin.good()) {	// no errors encountered with file stream so far
			getline(fin, lof);
			if ( (slashpos = lof.find("/")) != string::npos) {	// check if there's an IP prefix in file
				this->parse_prefixes(const_cast<char *>(lof.c_str()), ips_vect);	// remove cosntness using const_cast<type>
			} else {	// just IP not an IP prefix
				this->getIP( const_cast<char *>( lof.c_str() ) );
			}
		}
	} else {
		fprintf(stderr, "Could not open target file: \"%s\"\n", file);
		this->usage(stderr);
		exit(1);
	}


	fin.close();	// close file finally
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

int ArgsParser::get_threads() {
	return this->num_threads;
}