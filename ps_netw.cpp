
#include "ps_netw.hpp"
#include "ps_lib.hpp"	// for access to sets of IPs, ports, scans

// recall all global variables
queue<job_t> workQueue;

void JobMaker::createJobs() {

	set<string>::iterator ipsItr;
	set<int>::iterator portsItr;
	set<string>::iterator scansItr;

	for ( ipsItr = ips_set.begin(); ipsItr != ips_set.end(); ipsItr++) {
		for ( scansItr = scans_set.begin(); scansItr != scans_set.end(); scansItr++) {
			for ( portsItr = ports_set.begin(); portsItr != ports_set.end(); portsItr++ ) {
				job_t job;	// create a job
				job.ipAddr = *ipsItr;
				job.scanType = *scansItr;
				job.portNo = *portsItr;

				workQueue.push(job);	// enqueue job
			}
		}
	}

}