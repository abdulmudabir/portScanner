
#ifndef _PS_NETW_HPP_
#define _PS_NETW_HPP_


// standard libraries
#include <iostream>
#include <string>

// STL container/s
#include <queue>

using namespace std;

/* job description containing details of which
 *  IP address needs to be scanned on what all port numbers
 *  with which scans */
typedef struct job {
    string ipAddr;
    string scanType;
    int portNo;
} job_t;

// global variables
extern queue<job_t> workQueue;

class Jobber {
    public:
        void createJobs();
};


#endif