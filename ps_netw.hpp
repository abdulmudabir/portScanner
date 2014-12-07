
#ifndef _PS_NETW_HPP_
#define _PS_NETW_HPP_


// standard libraries
#include <iostream>

// networking libraries
#include <arpa/inet.h>

// STL container/s
#include <queue>
#include <map>
#include <vector>

using namespace std;

/* job description containing details of which
 *  IP address needs to be scanned on what all port numbers
 *  with which scans */
typedef struct job {
    char ipAddr[INET_ADDRSTRLEN];
    char scanType[5];
    int portNo;
} job_t;

typedef struct scan_result {
    char scanType[5];
    char portState[15]; // Open, Closed, Open|Filtered ?
} scan_result_t;

// global variables
extern queue<job_t> workQueue;  // queue of all jobs
extern vector<scan_result_t> scansResultsVect;  // vector of al scan results structures
extern map< int, vector<scan_result_t> > port2scanresultsMap;   // port number mapped to its vector of scan results structure
extern map< char *, map< int, vector<scan_result_t> > > resultsMap; // IP address mapped to port->scanresults map

class Jobber {
    public:
        void createJobs();
};


#endif