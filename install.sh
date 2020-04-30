#!/bin/sh

echo "Installing dirmon...."
cp ./dirmon /usr/bin/
echo "Dirmon installed"
echo
echo "Installing dirmon 'service'..."
mkdir /etc/dirmon
touch /etc/dirmon/monitored_directories
touch /etc/dirmon/audit_file
cp ./dirmon_service.sh /etc/dirmon/
cp ./dirmon_cron /etc/cron.d/
echo "Dirmon 'service' installed"
echo
echo "Write each directory you would like to monitor into"
echo "/etc/dirmon/monitored_directories , one per line"
echo
echo "Restart your system to begin monitoring"
echo
echo "See the result of your auditing in "
echo "/etc/dirmon/audit_file (feel free to remove this"
echo "file if you want to clear out old info)"
