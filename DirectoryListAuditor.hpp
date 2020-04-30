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
        struct fanotify_event_metadata * events;
        string output_filename;
        
        // Single private instance of the class
        static DirectoryListAuditor* instance;
        
        // Private constructors and assignment op to prevent user from
        // creating new instances
        DirectoryListAuditor();        
        DirectoryListAuditor(const DirectoryListAuditor&);
        DirectoryListAuditor& operator=(const DirectoryListAuditor&);

        fstream open_fstream_safely(string dir_list_filename);
        void write_event(struct fanotify_event_metadata * event,
                  ofstream& audit_output_file);
        string access_type_mask_to_string(unsigned long long mask);
        void send_permission_response(int event_fd, int fanotify_fd);
        bool requires_permission_response(unsigned long long mask);
        string get_user_of_pid(pid_t pid);
        string get_UTC_time_date();
        string get_filepath_from_fd(int fd);
        
        // Inputs:  List of directories to mount as themselves
        // Outputs: None
        // Return:  None, but exits with errno set according to failed mount
        //              call if mount fails
        void mark_directories(int fanotify_fd, unsigned int mark_flags,
                      uint64_t event_types_mask,
                      set<string> monitored_directories, 
                      set<string> excluded_directories);
        void mount_directories(set<string> directories);
        void clean_up();

        
    public:
        // Get a pointer to the Singleton static instance of the class 
        // (or create it if it doesn't exist)
        static DirectoryListAuditor* get_instance();
        

        // Intro:   This method prepares the DirectoryListAuditor for
        //              monitoring the given list of directories for the
        //              given types of access, and prepares the audit 
        //              output file. This method should only be called
        //              once because it has many side-effects that go
        //              beyond the scope of the object, such as mounting
        //              the given directories. This method does not actually
        //              start auditing the events to the output file. See
        //              audit_activity to begin auditing. Note that passing
        //              in a mask with permissions events will cause this
        //              call to lock up access to any files in the monitored
        //              directories until auditing begins.
        // Inputs:  event_types_mask : Defines which types of file access 
        //              events will be recorded for the list of directories
        //              (see man fanotify_mark)
        //          dir_list_filename : A full or relative filepath to the
        //              file containing the list of directories to monitor
        //          audit_output_filename : A full or relative path + filename
        //              where the activity should get audited to
        // Outputs: None
        // Return:  void
        void initialize(uint64_t event_types_mask, 
                         string dir_list_filename,
                         string audit_output_filename);

        // Intro:   Begin auditing to the audit output file prepared in
        //              initialize. Do not call this method until initialize has
        //              been called.
        // Inputs:  event_buf_size : The size of the event buffer. A good size is
        //              at least several times the size of a single struct 
        //              fanotify_event_metadata
        // Outputs: None
        // Return:  void
        void audit_activity(const size_t event_buf_size);

        // Intro:   This will allow the program to gracefully clean up all
        //              the extra mounted directories and the fanotify file
        //              descriptor on exit (important because it releases
        //              outstanding permissions accesses that could lock up
        //              the system)
        // Inputs:  signal_number : Just denotes what signal was sent. We will
        //              be catching SIGINT and SIGTERM, for command-line usage
        //              and service-style usage respectively (Catches ^C from
        //              command-line and SIGTERM when system shuts down)
        // Outputs: None
        // Return:  void
        static void signal_handler(int signal_number);
};

#endif