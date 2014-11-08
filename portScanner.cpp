
#include "ps_lib.h"

#include <iostream>

int main(int argc, char *argv[]) {

	ArgsParser ps_args;	// object to parse program arguments
	ps_args.parse_args(argc, argv);

	// print IPs
	cout << "\n"<< "=============== IPs to be scanned ===============" << endl << endl;
	ps_args.print_vectelems(ips_vect);

	// print ports
	cout << endl << "=============== Ports to scan ===============" << endl << endl;
	ps_args.print_vectelems(ports_vect);

	return 0;
}