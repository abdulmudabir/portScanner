
#include "ps_lib.h"

#include <iostream>

int main(int argc, char *argv[]) {

	ArgsParser ps_args;	// object to parse program arguments
	// ps_args.fill_resv_IPs();	// keep an account of all reserved IPs that are not allowed to be scanned
	ps_args.parse_args(argc, argv);

	// print IPs
	cout << "\n"<< "=============== IPs to be scanned ===============" << endl << endl;
	ps_args.print_vectelems(ips_vect);

	// print ports
	cout << endl << "=============== Ports to scan ===============" << endl << endl;
	ps_args.print_vectelems(ports_vect);

	// print number of threads to run
	cout << endl << "=============== Threads ===============" << endl << endl;
	cout << "Number fo threads specified: " << ps_args.get_threads() << endl << endl;

	return 0;
}