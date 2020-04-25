

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


#include <bits/stdc++.h> 
#include <iostream>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <unistd.h>

#include "boost/filesystem.hpp"

using namespace std;

const size_t max_mem_bytes = 4096;

int main(int argc, char * argv[])
{
    
    // Ensure we have the csv file argument
    if (argc < 2)
    {
        cerr << "diraudit: missing csv file operand" << endl;
        cerr << "Usage: diraudit [OPTION]... DIRECTORY_LIST_FILE" << endl;
        exit(1);
    }

    // Open the csv file containing the list of directories
    string dir_list_filename(argv[1]);

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
    int inotify_fd = inotify_init();
    if (inotify_fd == -1)
    {
        cerr << "diraudit: cannot initialize inotify file descriptor, errno:" << errno << endl;
        exit(errno);
    }

    // Add a watch for each directory and save the watch descriptors in a vector
    map<string,int> watch_descriptors;
    int watch_descriptor;
    for (int i = 0; i < directory_names.size(); i++)
    {
        watch_descriptor = inotify_add_watch(inotify_fd, 
                                             directory_names[i].c_str(),
                                             IN_ALL_EVENTS);
        if (watch_descriptor == -1)
        {
            cerr << "diraudit: cannot add watch at pathname '" 
                 << directory_names[i] << "'; (errno: "<<errno<<"); skipping directory..." << endl;
        }
        else
        {
            watch_descriptors[directory_names[i]] = watch_descriptor;
        }
    }
// TODO IN_ONLYDIR

    struct inotify_event * events = (struct inotify_event *) malloc(max_mem_bytes);
    ssize_t num_bytes_read = read(inotify_fd, events, max_mem_bytes);
    cout << "main(...): num_bytes_read == " << num_bytes_read << endl;
    if (num_bytes_read == -1)
    {
        cerr << "diraudit: error reading from inotify file descriptor" << endl;
        exit(errno);
    }
    unsigned num_events_read = num_bytes_read / sizeof(struct inotify_event);

    //ofstream

    for (int i = 0; i < num_events_read; i++)
    {
        
        struct inotify_event {
               int      wd;       /* Watch descriptor */
               uint32_t mask;     /* Mask describing event */
               uint32_t cookie;   /* Unique cookie associating related
                                     events (for rename(2)) */
               uint32_t len;      /* Size of name field */
               char     name[];   /* Optional null-terminated name */
           };
    }
}