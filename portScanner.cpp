
#include "ps_lib.h"

#include <iostream>

int main(int argc, char *argv[]) {

	ArgsParser ps_args;
	ps_args.parse_args(argc, argv);

	cout << "test, size of ports_vect: " << ports_vect.size() << endl;
	cout << "test, size of hosts_vect: " << hosts_vect.size() << endl;

	for ( int i = 0; i < int(hosts_vect.size()); i++ )
		cout << "test, IP addr: " << hosts_vect[i] << endl;

	return 0;
}