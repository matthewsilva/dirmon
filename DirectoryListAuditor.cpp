
#include "DirectoryListAuditor.hpp"

using namespace std;

// Singleton instance
DirectoryListAuditor * DirectoryListAuditor::instance = NULL;

void DirectoryListAuditor::mount_directories(set<string> directories)
{
    for (auto directory_name = directories.begin();
         directory_name != directories.end();
         directory_name++)
    {
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
        if (mount(directory_name->c_str(), directory_name->c_str(), 
                  "", MS_BIND, "") == -1)
        {
            cerr << "diraudit: cannot mount directory '" << *directory_name
                 << "'for monitoring, errno:" << strerror(errno) << endl;
            exit(errno);
        }
    }
}


void DirectoryListAuditor::mark_directories(int fanotify_fd, 
                                            unsigned int mark_flags,
                                            uint64_t event_types_mask,
                                            set<string> monitored_directories, 
                                            set<string> excluded_directories)
{
    for (auto directory_name = monitored_directories.begin();
         directory_name != monitored_directories.end();
         directory_name++)
    {
        cout << "main(...): Marking " << *directory_name << endl;
        // Mark the mounted directory for monitoring
        // (Pass in AT_FDCWD for directory file descriptor so that we can
        //  use relative pathnames if desired)
        if (fanotify_mark(fanotify_fd, mark_flags,
                          event_types_mask,
                          AT_FDCWD,
                          //directory_names[i].c_str()) == -1)
                          directory_name->c_str()) == -1)
        {
            cerr << "diraudit: cannot mark pathname '" 
                 << *directory_name << "'; (errno: "<<errno<<"); skipping directory..." << endl;
        }
    }

    // Specifically ignore events for the output file as to avoid
    // rapidly generating an infinite number of modify events if
    // the user wants to monitor the directory containing their 
    // output file 
    for (auto directory_name = excluded_directories.begin();
         directory_name != excluded_directories.end();
         directory_name++)
    {
        // Use IGNORED_MASK here to say that this should be ignored
        if (fanotify_mark(fanotify_fd, FAN_MARK_ADD | FAN_MARK_IGNORED_MASK,
                          event_types_mask,
                          AT_FDCWD,
                          //directory_names[i].c_str()) == -1)
                          directory_name->c_str()) == -1)
        {
            cerr << "diraudit: cannot unmark audit output file '" 
                 //<< directory_names[i] << "'; (errno: "<<errno<<"); skipping directory..." << endl;
                 << *directory_name << "'; (errno: "<<errno<<")" << endl;
        }
    }
}

string DirectoryListAuditor::get_filepath_from_fd(int fd)
{
    // Buffer for retrieving the filepaths of accessed files later
    char filepath[1024];
    string fd_path = "/proc/self/fd/";
    fd_path += to_string(fd);
    cout << "main(...): event->fd == " << fd << endl;
    size_t num_chars_retrieved = readlink(fd_path.c_str(), filepath, sizeof(filepath)-1);            
    if (num_chars_retrieved != -1)
    {
        filepath[num_chars_retrieved] = '\0';
        close(fd);
        return filepath;
    }
    else
    {
        return "FILE_NOT_FOUND";
    }
}

string DirectoryListAuditor::get_UTC_time_date()
{
    time_t system_time = time(0);
    tm * UTC_time = gmtime(&system_time);
    string UTC_time_str(asctime(UTC_time));
    // Remove trailing newline
    UTC_time_str.erase(UTC_time_str.end()-1);
    return UTC_time_str;
}

string DirectoryListAuditor::get_user_of_pid(pid_t pid)
{
    // We want to get the info from /proc/#pid/status and resolve
    // the UIDs to usernames, but only do these ops for a specific PID  
    int proc_flags = PROC_FILLSTATUS | PROC_FILLUSR | PROC_PID;
    // Create 0-terminated pid list            
    pid_t pid_list[2];
    pid_list[0] = pid;
    pid_list[1] = 0;
    PROCTAB * proc_tab = openproc(proc_flags, pid_list);
    
    // TODO see man readproc, don't want to alloc/free all the time
    //proc_t * found = (proc_t*) malloc(1024*sizeof(proc_t));
    proc_t * found = readproc(proc_tab, NULL);
    if (found)
    {
        string username(found->ruser);        
        freeproc(found);   // TODO see man readproc, don't want to alloc/free all the time 
        return username;
    }
    else
    {
        return "CANNOT_FIND_USER_DEAD_PROCESS";
    }
}
// Argument is an unsigned long long because __aligned is not allowed
bool DirectoryListAuditor::requires_permission_response(unsigned long long mask)
{
    if ((mask & FAN_ACCESS_PERM) || (mask & FAN_OPEN_PERM))
    {
        return true;
    }
    return false;
}

void DirectoryListAuditor::send_permission_response(int event_fd, 
                                                    int fanotify_fd)
{
    struct fanotify_response permission_event_response;
    permission_event_response.fd = event_fd;
    // TODO create option to map directories to yes/no access
    //if (
    permission_event_response.response = FAN_ALLOW;
    write (fanotify_fd, &permission_event_response, 
           sizeof(struct fanotify_response));
}

// Argument is an unsigned long long because __aligned is not allowed
string DirectoryListAuditor::access_type_mask_to_string(unsigned long long mask)
{
    string access_string = "(";
    if (mask & FAN_ACCESS)
    {
        access_string += "FAN_ACCESS;";
    }
    if (mask & FAN_OPEN)
    {
        access_string += "FAN_OPEN;";
    }
    if (mask & FAN_MODIFY)
    {
        access_string += "FAN_MODIFY;";
    }
    if (mask & FAN_CLOSE_WRITE)
    {
        access_string += "FAN_CLOSE_WRITE;";
    }
    if (mask & FAN_CLOSE_NOWRITE)
    {
        access_string += "FAN_CLOSE_NOWRITE;";
    }
    if (mask & FAN_Q_OVERFLOW)
    {
        access_string += "FAN_Q_OVERFLOW;";
    }
    if (mask & FAN_ACCESS_PERM)
    {
        access_string += "FAN_ACCESS_PERM;";
    }
    if (mask & FAN_OPEN_PERM)
    {
        access_string += "FAN_OPEN_PERM;";                
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
    return access_string;
}

void DirectoryListAuditor::write_event(struct fanotify_event_metadata * event,
                                       ofstream& audit_output_file)
{
    string event_str = "";
    // Get the filename of the file descriptor accessed
    event_str += get_filepath_from_fd(event->fd) + ",";

    // Get the time and date in UTC and add it to the audit file
    event_str += get_UTC_time_date() + ",";
    
    // Get the username of the process and add it to the audit file
    event_str += get_user_of_pid(event->pid) + ",";
    
    // Put the pid of the accessing process into the audit file
    event_str += to_string(event->pid) + ",";
    
    // Create string of access types to file
    // TODO break out into a function that takes a mask & rets a string
    event_str += access_type_mask_to_string(event->mask) + ",";
    
    audit_output_file << event_str << endl;
    
    audit_output_file.flush();
}

fstream DirectoryListAuditor::open_fstream_safely(string dir_list_filename)
{
    // Open the directory list file strictly to see if it exists
    int dir_list_fd = open(dir_list_filename.c_str(), O_PATH);
    if(dir_list_fd == -1)
    {
        // TODO Could check for errno either EACCESS or ENOENT to differentiate
        //      between bad permissions and nonexistent file
        cerr << "diraudit: cannot open directory list file '" 
             << dir_list_filename << "'; errno: '" << errno 
             << "'; No such file" << endl;        
        exit(errno);
    }
    else
    {
        close(dir_list_fd);
    }
    
    // Open the file containing the list of directories
    fstream dir_list_file;
    dir_list_file.open(dir_list_filename, ios::in);
    // If the file exists, but is not open, that must mean that the 
    // file exists but we are unable to access it, probably due to 
    // bad permissions
    if (!dir_list_file.is_open())
    {
        cerr << "diraudit: cannot open directory list file '" 
             << dir_list_filename << "': Unable to open file (bad permissions)" << endl;
        exit(3);
    }
    return dir_list_file;
}

DirectoryListAuditor::DirectoryListAuditor()
{
    
}

DirectoryListAuditor* DirectoryListAuditor::get_instance()
{
    if (instance == NULL)
    {
        instance = new DirectoryListAuditor();
    }
    return instance;
}

void DirectoryListAuditor::initialize(uint64_t event_types_mask, 
                                      string dir_list_filename,
                                      string audit_output_filename)
{
    // Create a signal handler to catch the SIGTERM shutdown signal signal     
    signal(SIGINT, signal_handler); //TODO if these are in separate objects, maybe we
                                    // have the directory list as a class data member
                                    // such that both classes can handle the signal

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

    // Open the directory list file
    fstream dir_list_file = open_fstream_safely(dir_list_filename);
    
    // Create or append to given audit output file
    audit_output_file = ofstream(audit_output_filename, 
                               ofstream::out | ofstream::app);


    // TODO FAN_MARK_ONLYDIR 
    // We want to add the marked directories as recursively monitored mounts
    unsigned int mark_flags = FAN_MARK_ADD | FAN_MARK_ONLYDIR | FAN_MARK_MOUNT;
    // TODO if (recursive_flag == true)
    // mark_flags |= FAN_MARK_MOUNT;

    // Retrieve all of the directories to monitor and store them in a set
    string directory_name;
    while(dir_list_file >> directory_name)
    {
        monitored_directories.insert(directory_name);
    }

    // Mount all of the directories that will be monitored (required
    // for recursive monitoring of directories and all subdirectories)
    mount_directories(monitored_directories);

    // Mark all of the directories for monitoring, and exclude the
    // audit output file (prevents infinite feedback loop of file
    // modifications)
    set<string> excluded_directories;
    excluded_directories.insert(audit_output_filename);
    mark_directories(fanotify_fd, mark_flags, event_types_mask,
                     monitored_directories, excluded_directories);
}

void DirectoryListAuditor::audit_activity(const size_t event_buf_size)
{
    // Create buffer for reading events
    struct fanotify_event_metadata * events =
        (struct fanotify_event_metadata *) malloc(event_buf_size);
    
    ssize_t num_bytes_read;
    
    // Loop until program is terminated externally
    for (;;)
    {
        cout << "main(...): Preparing to read fanotify fd" << endl;
        // TODO What is the behavior of read when the return is equal to the buffer size?    
        num_bytes_read = read(fanotify_fd, events, event_buf_size);
        cout << "main(...): num_bytes_read == " << num_bytes_read << endl;

        if (num_bytes_read == -1)
        {
            cerr << "diraudit: error reading from fanotify file descriptor" << endl;
            exit(errno);
        }
        // Iterate over the variably-sized event metadata structs   
        for (struct fanotify_event_metadata * event = events; 
             FAN_EVENT_OK(event,num_bytes_read); 
             event = FAN_EVENT_NEXT(event,num_bytes_read))
        {
            // If we have the same PID as the editing process, it means
            // we should skip this event, and write nothing to the audit
            // file (if we write to the audit file, it will cause an infinite
            // feedback loop of repeated file access and auditing)            
            if (event->pid == getpid()) 
            { 
                close(event->fd);
                continue;
            }
            // TODO maybe move this into separate for loop above to prevent
            // deadlock in case the user wants to monitory a file tree
            // containing the monitoring software, but also, we 
            // should consider that we should never mark the 
            // output file...
            if(requires_permission_response(event->mask))
            {
                send_permission_response(event->fd, fanotify_fd);
            }
            write_event(event, audit_output_file);
        }
    }
}

// TODO There should be a global collection of DirectoryMonitor objects
// that the signal handler should iterate through and call clean up methods
// on
// NOTE: The signal handler does not need to give permissions to outstanding
//       permission request events because closing the fanotify file descriptor
//       does that automatically
void DirectoryListAuditor::signal_handler(int signal_number) {

    cout << "dirmon: Ending gracefully due to signal (" 
         << signal_number << ")" << endl;
    close(instance->fanotify_fd);
    instance->audit_output_file.close();
    for (auto monitored_directory = instance->monitored_directories.begin();
              monitored_directory != instance->monitored_directories.end(); 
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