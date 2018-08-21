## Main Goal ##
My main goal was to do something as OSSEC, but in realtime.
It checks via inotify if CLOSE_WRITE is seen in kernel on a repository.
When a CLOSE_WRITE is done, it checks if the file was modified, if the file was executed, if the file was created.
Then, it makes a copy of file in a malicious_folder, and remove malicious file

### Usage ###
First of all : create backup (see requirements)

execution :
python /opt/honey_guardian/bin/notify_v2.0 -f /tmp/testfolder -m /opt/honey_guardian/resources/testfolder-md5sum.db

## Future of tool ##
Need to dameonize

## Requirements ##

sudo pip install pyinotify

### md5db ###
Make sure to create a md5sumdb with the following command :
find /tmp/testfolder/ -type f -exec md5sum '{}' \; > /opt/honey_guardian/resources/testfolder-md5sum.db

### safe backup ###
Make sure to create a safe backup used to restore modified files:
cp -R /tmp/testfolder /opt/honey_guardian/resources/safe_backup
Don't forget to keep the same directory tree as root (because it's badly coded, sorry)


