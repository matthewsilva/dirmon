

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

#include "boost/filesystem.hpp"

using namespace std;

const size_t max_mem_bytes = 4096;

int fanotify_fd;
ofstream audit_output_file;
set<string> monitored_directories;

void signal_handler(int signal_number) {
    cout << "dirmon: Ending gracefully due to signal (" 
         << signal_number << ")" << endl;
    close(fanotify_fd);
    audit_output_file.close();
    for (auto monitored_directory = monitored_directories.begin();
              monitored_directory != monitored_directories.end(); 
              monitored_directory++)
    //for (int i = 0; i < directory_names.size(); i++)
    {
        
        cout << "signal_handler(...): Unmounting directory '" 
             << *monitored_directory << "'" << endl;
        // Use the MNT_DETACH flag because the monitored directories
        // are likely in usage frequently, and we should wait until
        // they are not in use to unmount them 
        if (umount2(monitored_directory->c_str(), MNT_DETACH) == -1)
        {
            cerr << "diraudit: cannot unmount directory '" << *monitored_directory
                 << "', errno:" << strerror(errno) << endl;
        }
    }
    cout << "dirmon: Done with post-signal cleanup, exiting..." << endl;
    exit(signal_number);
}

int main(int argc, char * argv[])
{
    // TODO add options to set which things get recorded

    // Ensure we have the required arguments
    if (argc < 3)
    {
        cerr << "diraudit: missing csv file operand" << endl;
        cerr << "Usage: diraudit [OPTION]... DIRECTORY_LIST_FILE AUDIT_OUTPUT_FILENAME" << endl;
        exit(1);
    }    

    cout << "diraudit: Beginning with PID: " << getpid() << endl;

    string dir_list_filename(argv[1]);
    string audit_output_filename(argv[2]);

    // Create a signal handler to catch an interrupt signal     
    signal(SIGINT, signal_handler); //TODO if these are in separate objects, maybe we
                                    // have the directory list as a class data member
                                    // such that both classes can handle the signal

    // ---- BEGIN DirectoryMonitorCreator

    // Try to initialize fanotify
    // Set fanotify to give notifications on both accesses & attempted accesses    
    unsigned int monitoring_flags = FAN_CLASS_CONTENT;
    // Set event file to read-only and allow large files
    unsigned int event_flags = O_RDONLY;// | O_LARGEFILE;
    fanotify_fd = fanotify_init(monitoring_flags, event_flags);
    if (fanotify_fd == -1)
    {
        cerr << "diraudit: cannot initialize fanotify file descriptor, errno:" << errno << endl;
        exit(errno);
    }

    // Open the csv file containing the list of directories
    
    // Check if the dir list file exists using portable boost call
    if (!boost::filesystem::exists(dir_list_filename))
    {
        cerr << "diraudit: cannot open '" 
             << dir_list_filename << "': No such file" << endl;        
        exit(2);
    }
    
    fstream dir_list_file;
    dir_list_file.open(dir_list_filename, ios::in);

    // If the file exists, but is not open, that must mean that the 
    // file exists but we are unable to access it, probably due to 
    // bad permissions
    if (!dir_list_file.is_open())
    {
        cerr << "diraudit: cannot open '" 
             << dir_list_filename << "': Unable to open file (bad permissions)" << endl;
        exit(3);
    }

    // TODO FAN_MARK_ONLYDIR 
    // We want to add the marked directories as recursively monitored mounts
    unsigned int mark_flags = FAN_MARK_ADD | FAN_MARK_ONLYDIR | FAN_MARK_MOUNT;
    // TODO if (recursive_flag == true)
    // mark_flags |= FAN_MARK_MOUNT;
    // We want to monitor pretty much everything
    uint64_t event_types_mask = FAN_ACCESS | FAN_MODIFY |
                                FAN_CLOSE_WRITE | FAN_CLOSE_NOWRITE |
                                FAN_OPEN | // TODO FAN_Q_OVERFLOW |
                                //FAN_OPEN_PERM | FAN_ACCESS_PERM |
                                FAN_ONDIR | FAN_EVENT_ON_CHILD;
    
    // Add all of the directory names from the file into a vector
    vector<string> directory_names;
    string directory_name;
    while(dir_list_file >> directory_name)
    {
        cerr << "main(...): directory_name == " << directory_name << endl;
        // TODO maybe check to be sure that these are actually directories
        //      before adding to the set?
        monitored_directories.insert(directory_name);

        // Mount each of our directories
        // NOTE: We need to mount the directory as itself because: 
        // 1. fanotify requires that a directory be mounted to support the
        //    FA_MARK_MOUNT recursive directory monitoring flag.
        // 2. fanotify has a bug in Linux Kernel 3.17 onwards (see man) where 
        //    it is only able to pick up notifications from mountpoints 
        //    through the target mount point, and not the source. 
        // TODO This has a vulnerability in that any process that is already
        //      inside the directory before this mount occurs will not have
        //      any of its accesses monitored.
        if (mount(directory_name.c_str(), directory_name.c_str(), 
                  "", MS_BIND, "") == -1)
        {
            cerr << "diraudit: cannot mount directory '" << directory_name
                 << "'for monitoring, errno:" << strerror(errno) << endl;
            exit(errno);
        }
        cout << "main(...): Marking " << directory_name << endl;
        // Mark the mounted directory for monitoring
        // (Pass in -1 for directory file descriptor because we expect
        // absolute pathnames)
        if (fanotify_mark(fanotify_fd, mark_flags,
                          event_types_mask,
                          -1,
                          //directory_names[i].c_str()) == -1)
                          directory_name.c_str()) == -1)
        {
            cerr << "diraudit: cannot mark pathname '" 
                 //<< directory_names[i] << "'; (errno: "<<errno<<"); skipping directory..." << endl;
                 << directory_name << "'; (errno: "<<errno<<"); skipping directory..." << endl;
        }
    }
    
    // Specifically ignore events for the output file as to avoid
    // rapidly generating an infinite number of modify events if
    // the user wants to monitor the directory containing their 
    // output file 
    if (fanotify_mark(fanotify_fd, FAN_MARK_ADD | FAN_MARK_IGNORED_MASK,
                      event_types_mask,
                      -1,
                      //directory_names[i].c_str()) == -1)
                      audit_output_filename.c_str()) == -1)
    {
        cerr << "diraudit: cannot unmark audit output file '" 
             //<< directory_names[i] << "'; (errno: "<<errno<<"); skipping directory..." << endl;
             << audit_output_filename << "'; (errno: "<<errno<<")" << endl;
    }
    
    // ---- END DirectoryMonitorCreator


    // ---- BEGIN DirectoryAuditor

    // Create or append to given output file
    audit_output_file = ofstream(audit_output_filename, 
                               ofstream::out | ofstream::app);

    time_t system_time;
    tm * UTC_time;

    // Create buffer for reading events
    struct fanotify_event_metadata * events =
        (struct fanotify_event_metadata *) malloc(max_mem_bytes);
    struct fanotify_response permission_event_response;

    // Buffer for retrieving the filepaths of accessed files later
    char filepath[1024];

    ssize_t num_bytes_read;
    proc_t process_info;
    PROCTAB * proc_tab;

    // Loop until program is terminated externally
    for (;;)
    {
        cout << "main(...): Preparing to read fanotify fd" << endl;
        // TODO What is the behavior of read when the return is equal to the buffer size?    
        num_bytes_read = read(fanotify_fd, events, max_mem_bytes);
        cout << "main(...): num_bytes_read == " << num_bytes_read << endl;

        if (num_bytes_read == -1)
        {
            cerr << "diraudit: error reading from fanotify file descriptor" << endl;
            exit(errno);
        }
        
        struct fanotify_event_metadata * event;
        // Iterate over the variably-sized event metadata structs   
        // TODO FAN_EVENT_NEXT(meta, len)     
        for (char * event_ptr = reinterpret_cast<char*>(events); 
             event_ptr - reinterpret_cast<char*>(events) < num_bytes_read; 
             event_ptr += reinterpret_cast
                    <struct fanotify_event_metadata*>(event_ptr)->event_len)
        {
            event = reinterpret_cast<struct fanotify_event_metadata*>(event_ptr);
            
            // If we have the same PID as the editing process, it means
            // we should skip this event, and write nothing to the audit
            // file (if we write to the audit file, it will cause an infinite
            // feedback loop of repeated file access and auditing)            
            if (event->pid == getpid()) 
            { 
                close(event->fd);
                continue; 
            }            
            // Get the filename of the file descriptor accessed
            string fd_path = "/proc/self/fd/";
            fd_path += to_string(event->fd);
            cout << "main(...): event->fd == " << event->fd << endl;
            size_t num_chars_retrieved = readlink(fd_path.c_str(), filepath, sizeof(filepath)-1);            
            if (num_chars_retrieved != -1)
            {
                filepath[num_chars_retrieved] = '\0';
                audit_output_file << filepath << ",";
                close(event->fd);
            }
            else
            {
                audit_output_file << "FILE_NOT_FOUND" << ",";
            }

            // Get the time and date in UTC and add it to the audit file
            system_time = time(0);
            UTC_time = gmtime(&system_time);
            string UTC_time_str(asctime(UTC_time));
            // Remove trailing newline
            UTC_time_str.erase(UTC_time_str.end()-1);
            audit_output_file << UTC_time_str << ",";
            
            // Get the username of the process and add it to the audit file
            // We want to get the info from /proc/#pid/status and resolve
            // the UIDs to usernames, but only do these ops for a specific PID  
            int proc_flags = PROC_FILLSTATUS | PROC_FILLUSR | PROC_PID;
            // Create 0-terminated pid list            
            pid_t pid_list[2];
            pid_list[0] = event->pid;
            pid_list[1] = 0;
            proc_tab = openproc(proc_flags, pid_list);
            
            // TODO see man readproc, don't want to alloc/free all the time
            //proc_t * found = (proc_t*) malloc(1024*sizeof(proc_t));
            proc_t * found = readproc(proc_tab, NULL);
            if (found)
            {
                audit_output_file << found->ruser << ",";
                freeproc(found);   // TODO see man readproc, don't want to alloc/free all the time 
            }
            else
            {
                audit_output_file << "CANNOT_FIND_USER_DEAD_PROCESS" << ",";
            } 
            
            // Put the pid of the accessing process into the audit file
            audit_output_file << event->pid << ",";
            
            // Create string of access types to file
            // TODO maybe move this into separate for loop above to prevent
                    // deadlock in case the user wants to monitory a file tree
                    // containing the monitoring software, but also, we 
                    // should consider that we should never mark the 
                    // output file...
            // TODO break out into a function that takes a mask & rets a string
            string access_string = "(";
            if (event->mask & FAN_ACCESS)
            {
                access_string += "FAN_ACCESS;";
            }
            if (event->mask & FAN_OPEN)
            {
                access_string += "FAN_OPEN;";
            }
            if (event->mask & FAN_MODIFY)
            {
                access_string += "FAN_MODIFY;";
            }
            if (event->mask & FAN_CLOSE_WRITE)
            {
                access_string += "FAN_CLOSE_WRITE;";
            }
            if (event->mask & FAN_CLOSE_NOWRITE)
            {
                access_string += "FAN_CLOSE_NOWRITE;";
            }
            if (event->mask & FAN_Q_OVERFLOW)
            {
                access_string += "FAN_Q_OVERFLOW;";
            }
            if (event->mask & FAN_ACCESS_PERM)
            {
                access_string += "FAN_ACCESS_PERM;";
                permission_event_response.fd = event->fd;
                // TODO create option to map directories to yes/no access
                //if (
                permission_event_response.response = FAN_ALLOW;
                write (fanotify_fd,
                       &permission_event_response,
                       sizeof(struct fanotify_response));
            }
            if (event->mask & FAN_OPEN_PERM)
            {
                access_string += "FAN_OPEN_PERM;";                
                permission_event_response.fd = event->fd;
                // TODO create option to map directories to yes/no access
                //if (
                permission_event_response.response = FAN_ALLOW;
                write (fanotify_fd,  
                       &permission_event_response,
                       sizeof(struct fanotify_response));
            }

            // Remove terminating semicolon if needed, then add closing parens
            if (access_string[access_string.length()-1] == ';')
            {
                access_string[access_string.length()-1] = ')';
            }
            else
            {
                access_string += ")";
            }
            
            audit_output_file << access_string << ",";

            audit_output_file << endl;
            
            audit_output_file.flush();

    //o Text file must contain
    // Timestamp
    // User
    // Process ID
    // Access Type
            
            
           
        }
        
    }
    
}
/*
struct fanotify_event_metadata {
                   __u32 event_len;
                   __u8 vers;
                   __u8 reserved;
                   __u16 metadata_len;
                   __aligned_u64 mask;
                   __s32 fd;
                   __s32 pid;
               };
*/