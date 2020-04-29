#ifndef DIRECTORYLISTAUDITOR_H
#define DIRECTORYLISTAUDITOR_H

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

using namespace std;

class DirectoryListAuditor
{
    private:
        int fanotify_fd;
        ofstream audit_output_file;
        set<string> monitored_directories;
        
        // Single private instance of the class
        static DirectoryListAuditor* instance;
        
        fstream open_fstream_safely(string dir_list_filename);
        void write_event(struct fanotify_event_metadata * event,
                  ofstream& audit_output_file);
        string access_type_mask_to_string(unsigned long long mask);
        void send_permission_response(int event_fd, int fanotify_fd);
        bool requires_permission_response(unsigned long long mask);
        string get_user_of_pid(pid_t pid);
        string get_UTC_time_date();
        string get_filepath_from_fd(int fd);
        void mark_directories(int fanotify_fd, unsigned int mark_flags,
                      uint64_t event_types_mask,
                      set<string> monitored_directories, 
                      set<string> excluded_directories);
        void mount_directories(set<string> directories);
        
        // Private constructors and assignment op to prevent user from
        // creating new instances
        DirectoryListAuditor();        
        DirectoryListAuditor(const DirectoryListAuditor&);
        DirectoryListAuditor& operator=(const DirectoryListAuditor&);
        
    public:
        static DirectoryListAuditor* get_instance();
        void initialize(uint64_t event_types_mask, 
                         string dir_list_filename,
                         string audit_output_filename);
        void audit_activity(const size_t event_buf_size);
        static void signal_handler(int signal_number);
};

#endif