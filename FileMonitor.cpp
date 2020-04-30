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

// Builds the bitmask for the event types the user would like to audit
uint64_t build_mask_from_args(int argc, char * argv[]);

int main(int argc, char * argv[])
{
    if (argc == 2 && (string(argv[1]) == "--help" || string(argv[1]) == "-h"))
    {
        cout << "Usage: dirmon [OPTION]... DIRECTORY_LIST_FILE AUDIT_OUTPUT_FILENAME" << endl;
        cout << "NOTE: dirmon must be run as root (e.g. sudo)!" << endl;
        cout << "   If [OPTION] is omitted, all types of access " << endl;
        cout << "   are audited" << endl;        
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
        cerr << "dirmon: missing file operands" << endl;
        cerr << "Usage: dirmon [OPTION]... DIRECTORY_LIST_FILE AUDIT_OUTPUT_FILENAME" << endl;
        exit(1);
    }
    
    // Build the bitmask for the event types the user would like to audit
    uint64_t event_types_mask = build_mask_from_args(argc,argv);
    
    // Get the directory list and output filenames from the last two arguments
    string dir_list_filename(argv[argc-2]);
    string audit_output_filename(argv[argc-1]);
    
    // Get an instance of the singleton DirectoryListAuditor
    DirectoryListAuditor * auditor = DirectoryListAuditor::get_instance();

    // Prepare the auditor to be ready for recording the mask's event types
    // for the given directory list of directories to the output file given    
    auditor->initialize(event_types_mask, dir_list_filename,
                        audit_output_filename);

    // Continuously audit to the configured audit output file 
    // for configured activities within the configured
    // directories (the program will never return from this call, and
    // depends on a signal handler to terminate and clean up everything)
    auditor->audit_activity(max_mem_bytes);
    
}

// Build the bitmask for the event types the user would like to audit
uint64_t build_mask_from_args(int argc, char * argv[])
{    
    // Include ON_DIR and ON_CHILD by default
    uint64_t event_types_mask = FAN_ONDIR | FAN_EVENT_ON_CHILD; 
    // Options were not included, so everything will be monitored    
    if (argc == 3)
    {
        event_types_mask |= FAN_ACCESS | FAN_MODIFY |
                           FAN_CLOSE_WRITE | FAN_CLOSE_NOWRITE |
                           FAN_OPEN |
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
                cerr << "dirmon: Invalid option '" << argv[i] << "'" << endl;
                cerr << "dirmon: use diraudit --help for list of options" 
                     << endl;
                exit(1);
            }
        }
    }
    return event_types_mask;
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