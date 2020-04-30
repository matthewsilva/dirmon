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

// This singleton class is used to recursively monitor a set of directories 
//  (and all of their subdirectories) for a configurable set of access types.
//  The monitored activities will be written to the specified output file.
// Use get_instance() to get the instance of the class, call initialize() to
//  prepare it for auditing, and then call audit_activity() to start recording
//  to the output file
class DirectoryListAuditor
{
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

    private:
        // The fanotify file descriptor for the singleton
        int fanotify_fd;
        // A stream for the audit output file
        ofstream audit_output_file;
        // The filename of the audit output file
        string output_filename;
        // The set of directories to monitor access for
        set<string> monitored_directories;
        // A pointer to the event buffer used during auditing
        struct fanotify_event_metadata * events;
        
        // Single private instance of the class
        static DirectoryListAuditor* instance;
        
        // Private constructors and assignment op to prevent user from
        // creating new instances
        DirectoryListAuditor();        
        DirectoryListAuditor(const DirectoryListAuditor&);
        DirectoryListAuditor& operator=(const DirectoryListAuditor&);

        // Intro:   Opens the given filename safely and returns and fstream to
        //              it, exiting with an error if the file can't be 
        //              opened/found
        // Inputs:  dir_list_filename : the file to open an fstream for
        // Outputs: None
        // Return:  An open fstream for the filename, exits if impossible
        fstream open_fstream_safely(string dir_list_filename);

        // Intro:   Extracts the pertinent information from an fanotify event
        //              to a string and writes it to the given stream
        // Input:   event : The fanotify event to write to a stream
        //          audit_output_file : The stream to write the info to
        // Outputs: None
        // Return:  void 
        void write_event(struct fanotify_event_metadata * event,
                  ofstream& audit_output_file);

        // Intro:   Forms a string listing all the access types in the
        //              given fanotify_mark event access type mask
        // Inputs:   mask : the struct fanotify_event_metadata.mask
        //              event access type mask
        // Outputs: None
        // Return:  A string of all the access types, enclosed in
        //              parentheses and separated by semicolons
        string access_type_mask_to_string(unsigned long long mask);

        // Intro:   Sends a struct fanotify_response for the given permission
        //              event file descriptor to the fanotify file descriptor
        // Inputs:  event_fd : the event file descriptor to generate a
        //              permissions response for
        //          fanotify_fd : the fanotify file descriptor to send
        //              the permission response to
        // Outputs: None
        // Return:  void
        void send_permission_response(int event_fd, int fanotify_fd);

        // Intro:   Determines whether the given fanotify_mark event access
        //              type mask denotes a permission event requiring
        //              a response
        // Inputs:  mask : the struct fanotify_event_metadata.mask
        //              event access type mask
        // Outputs: None
        // Return:  Does the mask contain a permission event requiring 
        //              a response?
        bool requires_permission_response(unsigned long long mask);

        // Intro:   Gets the username who owned the process of the given pid
        // Inputs:  pid : the pid to fetch the username for using readproc()
        // Outputs: None
        // Return:  Real username of user who owned pid, or 
        //              CANNOT_FIND_USER_DEAD_PROCESS if readproc() didn't
        //              find the pid
        string get_user_of_pid(pid_t pid);

        // Intro:   Gets the current UTC time and date as a string
        // Inputs:  None
        // Outputs: None
        // Return:  A string containing the current UTC time and date
        string get_UTC_time_date();
        
        // Intro:   Takes an open file descriptor and returns the filepath
        //              of the file it was opened for
        // Inputs:  fd : the open file descriptor
        // Outputs: None
        // Return:  The filepath that the file descriptor was opened for,
        //              or FILE_NOT_FOUND if the file descriptor wasn't open
        string get_filepath_from_fd(int fd);
        
        // Intro:   Marks a set of directories for monitoring on the given
        //              fanotify file descriptor for the given types of
        //              events, using the mark flags provided. Marks the
        //              set of excluded directories to ignore.
        // Inputs:  fanotify_fd : the fanotify file descriptor to mark these
        //              directories for
        //          mark_flags : the marking flags given to fanotify for marking
        //              these directories
        //          event_types_mask : the mask representing the access types
        //              you would like to mark on these directories for
        //              monitoring 
        //          monitored_directories : set of directories to mark for
        //              monitoring
        //          excluded_directories : set of directories to mark for
        //              ignoring
        // Outputs: None
        // Return:  void
        void mark_directories(int fanotify_fd, unsigned int mark_flags,
                      uint64_t event_types_mask,
                      set<string> monitored_directories, 
                      set<string> excluded_directories);

        // Intro:   Mounts a set of directories as themselves with bind option
        // Inputs:  directories : set of directories to mount as themselves
        //              (e.g. mount --bind /path/of/dir /path/of/dir)
        // Outputs: None
        // Return:  void, but exits with errno set according to failed mount
        //              call if mount fails
        void mount_directories(set<string> directories);

        // Intro:   Cleans up the changed system state created in initialize
        //              (e.g. unmounts all directories)         
        // Inputs:  None
        // Outputs: None
        // Return:  void
        void clean_up();

        
    
};

#endif