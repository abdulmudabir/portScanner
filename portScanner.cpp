
#include "ps_lib.hpp"
#include "ps_netw.hpp"

// standard libraries
#include <iostream>
#include <ctime>

int main(int argc, char *argv[]) {

	/* display start time */
	time_t init_time, fin_time;	// for storing time values at beginning of program execution
	struct tm *abouttime;	// store current time details in this structure
	char buffer[100];	// string to display to stdout
	time(&init_time);	// get current time
	abouttime = localtime(&init_time);
	strftime(buffer, sizeof buffer, "\nportScanner started at %F %T %Z.", abouttime);
	cout << buffer << endl;

	ArgsParser ps_args;	// object to parse program arguments
	// ps_args.fill_resv_IPs();	// keep an account of all reserved IPs that are not allowed to be scanned
	ps_args.parse_args(argc, argv);

	// print IPs
	cout << "\n"<< "=============== IPs to be scanned ===============" << endl << endl;
	ps_args.print_setelems(ips_set);

	// print ports
	cout << endl << "=============== Ports to scan ===============" << endl << endl;
	ps_args.print_setelems(ports_set);

	// print number of threads to run
	cout << endl << "=============== Threads ===============" << endl << endl;
	cout << "Number of threads specified: " << ps_args.get_threads() << endl << endl;

	// print type/s of scans specified
	cout << endl << "=============== Scan types ===============" << endl << endl;
	ps_args.print_setelems(scans_set);
	cout << endl;

	// create a work queue
	JobMaker jobman;
	jobman.createJobs();


	/* display end time */
	time(&fin_time);	// get time at end
	abouttime = localtime(&fin_time);
	memset(buffer, 0x0, sizeof buffer);	// flush out char buffer
	strftime(buffer, sizeof buffer, "portScanner ended at %F %T %Z.", abouttime);
	fprintf( stdout, "%s Scan took %.3f seconds.\n\n", buffer, difftime(fin_time, init_time) );	// output difference in start and end time too

	return 0;
}