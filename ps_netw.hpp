
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
extern queue<job_t> workQueue;
extern vector<scan_result_t> scansResults;
extern map< char *, map< int, vector<scan_result_t> > > resultsMap;

class Jobber {
    public:
        void createJobs();
};


#endif