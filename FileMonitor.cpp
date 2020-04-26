

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
#include <sys/fanotify.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <unistd.h>

#include "boost/filesystem.hpp"

using namespace std;

const size_t max_mem_bytes = 4096;

int main(int argc, char * argv[])
{
    
    // Ensure we have the csv file argument
    if (argc < 3)
    {
        cerr << "diraudit: missing csv file operand" << endl;
        cerr << "Usage: diraudit [OPTION]... DIRECTORY_LIST_FILE AUDIT_OUTPUT_FILENAME" << endl;
        exit(1);
    }

    string dir_list_filename(argv[1]);
    string audit_output_filename(argv[2]);

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

    // Add all of the directory names from the file into a vector
    vector<string> directory_names;
    string directory_name;
    while(dir_list_file >> directory_name)
    {
        cerr << "main(...): directory_name == " << directory_name << endl;
        directory_names.push_back(directory_name);
    }

    // Try to initialize inotify
    // Set fanotify to give notifications on both accesses & attempted accesses    
    unsigned int monitoring_flags = FAN_CLASS_CONTENT;
    // Set event file to read-only and allow large files
    unsigned int event_flags = O_RDONLY;// TODO || O_LARGEFILE;
    int fanotify_fd = fanotify_init(monitoring_flags, event_flags);
    if (fanotify_fd == -1)
    {
        cerr << "diraudit: cannot initialize fanotify file descriptor, errno:" << errno << endl;
        exit(errno);
    }
    
    // Mark each directory and save the mark descriptors    
    map<string,int> mark_descriptors;
    int mark_descriptor;
    // TODO FAN_MARK_ONLYDIR 
    unsigned int mark_flags = FAN_MARK_ADD;// | FAN_MARK_ONLYDIR;
    uint64_t event_types_mask = FAN_ACCESS | FAN_MODIFY; /*|
                                FAN_CLOSE_WRITE | FAN_CLOSE_NOWRITE |
                                FAN_OPEN | FAN_Q_OVERFLOW |
                                FAN_OPEN_PERM | FAN_ACCESS_PERM |
                                FAN_ONDIR;*/
    // Pass in -1 for directory file descriptor because we expect
    // absolute pathnames
    int directory_fd = -1;
    for (int i = 0; i < directory_names.size(); i++)
    {
        // Mark the directory for viewing
        if (fanotify_mark(fanotify_fd, mark_flags,
                          event_types_mask,
                          directory_fd,
                          directory_names[i].c_str()) == -1)
        {
            cerr << "diraudit: cannot add watch at pathname '" 
                 << directory_names[i] << "'; (errno: "<<errno<<"); skipping directory..." << endl;
        }
    //    watch_descriptors[directory_names[i]] = watch_descriptor;
    }

    // Create 
    ofstream audit_output_file(audit_output_filename);

    struct fanotify_event_metadata * events =
        (struct fanotify_event_metadata *) malloc(max_mem_bytes);
    // TODO What is the behavior of read when the return is equal to the buffer size?    
    ssize_t num_bytes_read;
    time_t current_time;
    num_bytes_read = read(fanotify_fd, events, max_mem_bytes);
    cout << "main(...): num_bytes_read == " << num_bytes_read << endl;
    if (num_bytes_read == -1)
    {
        cerr << "diraudit: error reading from fanotify file descriptor" << endl;
        exit(errno);
    }
    
    
    struct fanotify_event_metadata * event;
    for (char * event_ptr = reinterpret_cast<char*>(events); 
         event_ptr - reinterpret_cast<char*>(events) < num_bytes_read; 
         event_ptr += reinterpret_cast
                <struct fanotify_event_metadata*>(event_ptr)->event_len)
    {
        event = reinterpret_cast<struct fanotify_event_metadata*>(event_ptr);


        cout << "pid == " << event->pid << endl;   
//o Text file must contain
// Timestamp
// User
// Process ID
// Access Type
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
    }
}