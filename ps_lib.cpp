
/*
 * References:
 * 	http://linux.die.net/man/3/inet_addr 					// convert IP to binary
 * 	http://man7.org/linux/man-pages/man3/inet_pton.3.html
 * 	http://linux.die.net/man/3/inet_aton
 * 	http://stackoverflow.com/questions/2182002/convert-big-endian-to-little-endian-in-c-without-using-provided-func
 */

#include "ps_lib.h"

// standard libraries
#include <iostream>
#include <cstdio>
#include <cstring>
#include <cstdlib>

/* recall all global variables */
vector<int> ports_vect;
vector<int>::iterator vect_itr;
vector<string> hosts_vect;

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
				this->gethosts(optarg);
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

void ArgsParser::gethosts(char *ip) {
	struct hostent *hostinfo;	// hostent struct contains information like IP address, host name, etc.

	if ( (hostinfo = gethostbyname(ip)) == NULL) {
		fprintf(stderr, "Error: Host not found !\n");
		exit(1);
	}

	struct sockaddr_in hostip;	// to store IP address data structure
	hostip.sin_family = AF_INET;	// set Internet Addressing as IP family type
	memcpy( (char *) &hostip.sin_addr.s_addr, (char *) hostinfo->h_addr_list[0], strlen((char *) hostinfo->h_addr_list) );	// register IP address of host specified at cli
	
	string ip_holder(inet_ntoa(hostip.sin_addr));
	cout << "testing, ip_holder: " << ip_holder << endl;

	hosts_vect.push_back(ip_holder);

}

void ArgsParser::parse_prefixes(char *prefix) {
	
	char *token;	// to tokenize IP prefix to separate forward-slash part
	char delim[] = "/";
	char netw_addr[INET_ADDRSTRLEN], lead_bits[2];	// for IP prefix format: "network-addr/lead-bits"
	int i = 0;
	
	memset(netw_addr, 0x00, sizeof netw_addr);	// zero-out buffers initially
	memset(lead_bits, 0x00, sizeof lead_bits);
	// char addr_buf[sizeof(struct in_addr)];	// to store numeric address of IP; struct size: 4 bytes for IPv4
	// memset(addr_buf, 0x00, sizeof addr_buf);
	for ( (token = strtok(prefix, delim)); (token != NULL && i < 2); (token = strtok(NULL, delim)), i++ ) {
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
		fprintf(stderr, "Something's not right with the IP prefix.\n");
		this->usage(stderr);
		exit(1);
	}

	// IP VALIDATION NEEDED HERE, BEFORE USING inet_aton()

	unsigned int uint_addr = 0;	// to store network byte order long of string IP
	if ( (i = inet_aton(netw_addr, (struct in_addr *) &uint_addr)) < 1 ) {	// convert IP to long in network byte order; inet_aton() returns non-zero for SUCCESS
		fprintf(stderr, "Error: Could not understand network address in IP prefix.\n");
		this->usage(stderr);
		exit(1);
	}
	
	unsigned int rev_endn = this->convert_endianness(uint_addr);
	// cout << "testing, revend: " << rev_endn << endl;

	// create netmask
	unsigned int netw_bits = atoi(lead_bits);
	unsigned int netmask = 4294967295 << (32 - netw_bits);
	cout << "testing, netmask: " << netmask << endl;

	unsigned int masked_rev_endn = rev_endn & netmask;	// apply Netmask
	masked_rev_endn = this->convert_endianness(masked_rev_endn);
	cout << "testing, masked_rev_endn: " << masked_rev_endn << endl;
	char next_ip[20];
	memset(next_ip, 0x00, sizeof next_ip);
	sprintf( next_ip, "%s", inet_ntoa( *(struct in_addr *) &masked_rev_endn ) );
	cout << "testing, first IP: " << next_ip << endl;

	// get next IP addr in range (NOT WORKING !!)
	masked_rev_endn = masked_rev_endn | 0x00000001;
	memset(next_ip, 0x00, sizeof next_ip);
	sprintf( next_ip, "%s", inet_ntoa( *(struct in_addr *) &masked_rev_endn ) );	
	cout << "testing, next IP: " << next_ip << endl;

}

/* converts endianness of a number (specifically from little-endian to big-endian for x86 machines) */
inline unsigned int ArgsParser::convert_endianness(unsigned int n) {
	return ( (n << 24) | ( (n << 8) & 0xff0000 ) | ( (n >> 8) & 0xff00 ) | (n >> 24) );
}