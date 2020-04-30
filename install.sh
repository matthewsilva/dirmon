#!/bin/sh

echo "Downloading files..."
echo
wget https://github.com/matthewsilva/dirmon/raw/master/bins/dirmon
wget https://raw.githubusercontent.com/matthewsilva/dirmon/master/dirmon_cron
wget https://raw.githubusercontent.com/matthewsilva/dirmon/master/dirmon_service.sh
echo
echo "Finished donwloading"
echo
echo "Installing dirmon...."
chmod 777 ./dirmon
cp ./dirmon /usr/bin/
echo "Dirmon installed"
echo
echo "Installing dirmon 'service'..."
mkdir /etc/dirmon
touch /etc/dirmon/monitored_directories
touch /etc/dirmon/audit_file
chmod 777 ./dirmon_services.sh
cp ./dirmon_service.sh /etc/dirmon/
# permissions 600 required for jobs in cron.d
chmod 600 ./dirmon
cp ./dirmon_cron /etc/cron.d/
echo "Dirmon 'service' installed"
echo
echo "Cleaning up files..."
rm -f ./dirmon
rm -f ./dirmon_service.sh
rm -f ./dirmon_cron
echo "Files cleaned up"
echo
echo "Write each directory you would like to monitor into"
echo "/etc/dirmon/monitored_directories , one per line"
echo
echo "Restart your system to begin monitoring"
echo
echo "See the result of your auditing in "
echo "/etc/dirmon/audit_file (feel free to remove this"
echo "file if you want to clear out old info)"
echo 
echo "Restart your system after reconfiguring"
echo "/etc/dirmon/monitored_directories if you want to"
echo "monitor more directories"