

/* 

File Audit System

Description
Create file monitoring software that will log file access to configured 
    directories on the system.
Requirements
 Software must be easily installed and configured
 Software must monitor configured directories for file access
o Auditing must run from OS startup to shutdown
o Audit must be written to text file on local system
o Text file must contain
 Timestamp
 User
 Process ID
 Access Type
Technical Requirements
Show off the way you code
Pick an object-oriented language
Upload your source to a public source repository or provide the 
    full source by a different means
Include any notes or thoughts on the project

*/

// TODO cron ?
// TODO install dirmon binary in $PATH ?

#include <bits/stdc++.h> 
#include <ctime>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <proc/readproc.h>
#include <signal.h>
#include <sys/fanotify.h>
#include <sys/inotify.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "DirectoryListAuditor.hpp"

using namespace std;

const size_t max_mem_bytes = 4096;

// Build the bitmask for the event types the user would like to audit
uint64_t build_mask_from_args(int argc, char * argv[])
{    
    // Include ON_DIR and ON_CHILD by default
    uint64_t event_types_mask = FAN_ONDIR | FAN_EVENT_ON_CHILD; 
    // Options were not included, so everything will be monitored    
    if (argc == 3)
    {
        event_types_mask = FAN_ACCESS | FAN_MODIFY |
                           FAN_CLOSE_WRITE | FAN_CLOSE_NOWRITE |
                           FAN_OPEN | // TODO FAN_Q_OVERFLOW |
                           FAN_OPEN_PERM | FAN_ACCESS_PERM;
    }
    // Options were included, so they need to be parsed    
    else if (argc > 3)
    {
        for (int i = 1; i < argc-2; i++)
        {
            string current_arg(argv[i]);
            if (current_arg == "--ACCESS") {
                event_types_mask |= FAN_ACCESS;
            }
            else if (current_arg == "--MODIFY") {
                event_types_mask |= FAN_MODIFY;
            }
            else if (current_arg == "--CLOSE_WRITE") {
                event_types_mask |= FAN_CLOSE_WRITE;
            }
            else if (current_arg == "--CLOSE_NOWRITE") {
                event_types_mask |= FAN_CLOSE_NOWRITE;
            }
            else if (current_arg == "--OPEN") {
                event_types_mask |= FAN_OPEN;
            }
            else if (current_arg == "--OPEN_PERM") {
                event_types_mask |= FAN_OPEN_PERM;
            }
            else if (current_arg == "--ACCESS_PERM") {
                event_types_mask |= FAN_ACCESS_PERM;
            }
            else if (current_arg == "--ALL") {
                event_types_mask |= FAN_ACCESS | FAN_MODIFY |
                       FAN_CLOSE_WRITE | FAN_CLOSE_NOWRITE |
                       FAN_OPEN | // TODO FAN_Q_OVERFLOW |
                       FAN_OPEN_PERM | FAN_ACCESS_PERM;
            }
            else {
                cerr << "diraudit: Invalid option '" << argv[i] << "'" << endl;
                cerr << "diraudit: use diraudit --help for list of options" 
                     << endl;
                exit(1);
            }
        }
    }
    return event_types_mask;
}

int main(int argc, char * argv[])
{
    // TODO add options to set which things get recorded

    if (argc == 2 && (string(argv[1]) == "--help" || string(argv[1]) == "-h"))
    {
        cout << "Usage: diraudit [OPTION]... DIRECTORY_LIST_FILE AUDIT_OUTPUT_FILENAME" << endl;
        cout << "   [OPTION]... is composed of one or more of " << endl;
        cout << "   the following options (see man fanotify_mark" << endl;
        cout << "   for explanations of each option)" << endl;
        cout << "       --ACCESS" << endl;
        cout << "       --MODIFY" << endl;
        cout << "       --CLOSE_WRITE" << endl;
        cout << "       --CLOSE_NOWRITE" << endl;
        cout << "       --OPEN" << endl;
        cout << "       --OPEN_PERM" << endl;
        cout << "       --ACCESS_PERM" << endl;
        cout << "       --ALL" << endl;
        return 0;
    }

    // Ensure we have the required arguments
    else if (argc < 3)
    {
        cerr << "diraudit: missing file operands" << endl;
        cerr << "Usage: diraudit [OPTION]... DIRECTORY_LIST_FILE AUDIT_OUTPUT_FILENAME" << endl;
        exit(1);
    }
    
    // Build the bitmask for the event types the user would like to audit
    uint64_t event_types_mask = build_mask_from_args(argc,argv);
    
    cout << "diraudit: Beginning with PID: " << getpid() << endl;

    // Get the directory list and output filenames from the last two arguments
    string dir_list_filename(argv[argc-2]);
    string audit_output_filename(argv[argc-1]);
    
    
    // TODO Directory auditor should actually take dirs.txt because it needs to
    // mark dirs.txt and update other marks anytime that dirs.txt changes
    DirectoryListAuditor * auditor = DirectoryListAuditor::get_instance();
    auditor->initialize(event_types_mask, dir_list_filename,
                        audit_output_filename);
    // Continuously audit to the configured audit output file 
    // for configured activities within the configured
    // directories (the program will never return from this call, and
    // depends on a signal handler to terminate and clean up everything)
    auditor->audit_activity(max_mem_bytes);
    
}
/*
struct fanotify_event_metadata {
                   __u32 event_len;
                   __u8 vers; // TODO check vers?
                   __u8 reserved;
                   __u16 metadata_len;
                   __aligned_u64 mask;
                   __s32 fd;
                   __s32 pid;
               };
*/