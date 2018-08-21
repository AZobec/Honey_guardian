#!/usr/bin/python
#################################################
#       Author : ARNAUD ZOBEC                   #
#       date : 21.08.2018                       #
#    version 2.21-08-2018.01                    #
#                                               #
# examples of piynotify : https://github.com/seb-m/pyinotify/tree/master/python2/examples
#
# doc of pyinotify : http://seb.dbzteam.org/pyinotify/
# Goal is to notify when a change occurs in /var/www/html #
# Check if the new file is launched in ps, and kill it if necessary
#################################################
import pyinotify, time, socket, hashlib, json
from threading import Thread
from time import sleep
import signal
from subprocess import check_output
import os
from shutil import copyfile
from os import path as os_path
import optparse
import sys

#Global variables (i know it sucks)
malicious_backup = "/opt/honey_guardian/malicious_folder/"
watched_folder = ""
watched_md5sum = "/opt/honey_guardian/resources/www-md5sum.db"
log_output = "/var/ossec/logs/alerts/alerts.json"
def md5Checksum(filePath):
    with open(filePath, 'rb') as fh:
        m = hashlib.md5()
        while True:
            data = fh.read(8192)
            if not data:
                break
            m.update(data)
        return m.hexdigest()


#### DEBUT THREADED_FUNCTION ####
# threaded_function() aims to create a thread 
# in order to create logs
# and backup files
# and restore old backups
#
def threaded_function(event_name, event_pathname, event_md5sum, actual_time):
    sys.stdout = open(log_output, 'a')
    copy_done = True

    if os.path.isfile(event_pathname):
        pass
    else:
        sys.exit()
    #### THREADING IS RUNNING ####
    
    flag_done=False
    #Firt of all - create a copy of file in malicious_folder
    copydst = malicious_backup + event_name +"_"+event_md5sum
    try:
        copyfile(event_pathname, copydst)
    except:
        exit
    #copy_done=True
    #Second step - kill a possible execution of it and notify it
    out = check_output(["ps", "-ef"])
    for line in out.splitlines():
        if event_name in line:
            sleep(5)
            pid = int(line.split()[1])
            #print "PID OF "+ event_name +" is : --"+ str(pid) +"--\n"
            try:
                os.kill(pid, signal.SIGKILL)
                #### Execution of "+ event_name+ " was killed ####\n"
                full_log = "Process - "+ event_name +" - of pid -- "+ str(pid)+" -- was killed"
                _str = json.dumps({"rule":{"level":8,"comment":"A malicious process was aborted.","sidid":12554,"group":"ossec,syscheck,processcheck,"},"id":time.time(),"TimeStamp":time.time(),"decoder":"processcheck_detected_anomaly","location":"process_check","full_log": full_log,"process":{"name":event_name, "pid":str(pid),"path":event_pathname,"md5":event_md5sum},"hostname":socket.gethostname()})
                print _str
    
               #NOW save the file in a backup_malicious folder
            except:
                full_log = "ERROR - Process - "+ event_name +" - of pid -- "+ str(pid)+" -- was NOT killed"
                _str = json.dumps({"rule":{"level":8,"comment":"ERROR - A malicious process was NOT aborted.","sidid":12555,"group":"ossec,syscheck,processcheck,"},"id":time.time(),"TimeStamp":time.time(),"decoder":"processcheck_detected_anomaly_error","location":"process_check_error","full_log": full_log,"process":{"name":event_name, "pid":str(pid),"path":event_pathname,"md5":event_md5sum},"hostname":socket.gethostname()})
                print _str
                #print "#### ERROR WHEN KILLING EVENT ####\n"
     
    #Verify if source was in known file. If in knwown file, restore it at the end
    with open(watched_md5sum) as f:
        for line in f:
            if event_pathname in line:
                # IT MEANS THAT A KNOWN FILE WAS MODIFIED AND NOT ADDED
                actual_path = os_path.abspath(os_path.split(__file__)[0])
                #ACTUAL_PATH should be at installpath/honey_guardian/bin 
                known_file_location = line.split('  ')[1]
                backup_path=actual_path[:-4]+"/resources/safe_backup"+known_file_location[:-1]
                if event_md5sum != line.split('  ')[0]:
                ## NOW WE HAVE TO RESTORE THE FILE
                    try:
                        #HERE IT'S WHEN THE FILE WAS TRULY MODIFIED
                        #SO HERE WE CAN PRINT that file was modified
                        copyfile(backup_path,event_pathname)
                        full_log = "File '"+ event_pathname +"' was modified in the filesystem"
                        _str = json.dumps({"rule":{"level":7,"comment":"File modified in the system. Backup file was successfuly restored.","sidid":13554,"group":"ossec,syscheck,"},"id":time.time(),"TimeStamp":time.time(),"decoder":"syscheck_integrity_changed","location":"syscheck","full_log": full_log,"file":{"name":event_name,"path":event_pathname,"md5_after":event_md5sum},"hostname":socket.gethostname()})
                        print _str
                        flag_done=True
                    except:
                        full_log = "ERROR - File '"+ event_pathname +"' was NOT RESTORED"
                        _str = json.dumps({"rule":{"level":7,"comment":"ERROR - BACKUP WAS NOT RESTORED - File modified in the system. Backup file was NOT restored.","sidid":13554,"group":"ossec,syscheck,"},"id":time.time(),"TimeStamp":time.time(),"decoder":"syscheck_integrity_changed","location":"syscheck","full_log": full_log,"file":{"name":event_name,"path":event_pathname,"md5_after":event_md5sum},"hostname":socket.gethostname()})
                        print _str
                        #print "#### ERROR WHEN COPYING FILE ####"

                else:
                    # HERE IS THE RESIDUE OF the copy above
                    #SO WE DON'T PRINT THE MODIFIED FILE JUST SET THE FLAG TO True
                    flag_done=True
                    #print "\n#### THIS IS THE OLD BACKUP SO NO PRINT####\n"
    
    if flag_done == False:
        #print that a file was newlycreated
        full_log = "New file '"+ event_pathname +"' added to the filesystem"
        _str = json.dumps({"rule":{"level":7,"comment":"File added to the system.","sidid":554,"group":"ossec,syscheck,"},"id":time.time(),"TimeStamp":time.time(),"decoder":"syscheck_integrity_changed","location":"syscheck","full_log": full_log,"file":{"name":event_name,"path":event_pathname,"md5_after":event_md5sum},"hostname":socket.gethostname()})
        print _str
        flag_done = True
    #DESTROY MALICIOUS FILE
    #if copy_done == False:
        try:
            os.remove(event_pathname)
        except:
    #            #print "Problem"
            full_log = "ERROR - file '"+ event_pathname +"' WAS NOT DELETED from the filesystem"
            _str = json.dumps({"rule":{"level":7,"comment":"ERROR - File not deleted from the system.","sidid":12556,"group":"ossec,syscheck,"},"id":time.time(),"TimeStamp":time.time(),"decoder":"syscheck_integrity_changed","location":"syscheck","full_log": full_log,"file":{"name":event_name,"path":event_pathname,"md5_after":event_md5sum},"hostname":socket.gethostname()})
            print _str
#### FIN THREADED_FUNCTION ####


def my_callback(evt):
    actual_time = time.time()
    event_md5sum = md5Checksum(evt.pathname)
    sleep(1)
    thread = Thread(target = threaded_function, args=[evt.name,evt.pathname,event_md5sum,actual_time])
    try:
        #Thread is called to wait for process to be activated, and then killed
        thread.start()
    except:
        LOG_FILE=open("/var/log/pyinotify_error.log","a")
        LOG_FILE.write("@"+ str(actual_time)+"THREAD START ERROR\n")
        LOG_FILE.close()



if __name__ == "__main__":
    
    #Gestion arguments

    parser = optparse.OptionParser()
    parser.add_option("-f", "--folder", dest = 'watched_folder', help = "Folder to watch CLOSE_WRITE events", metavar = "FOLDER", default = False)
    parser.add_option("-m", "--md5", dest = 'watched_md5sum', help = "md5sum DB of watched folder", metavar = "MD5", default = False)

    options,args = parser.parse_args()

    if options.watched_folder != False:
        watched_folder = options.watched_folder
    if options.watched_md5sum != False:
        watched_md5sum = options.watched_md5sum

    if len(sys.argv)==1:
        parser.print_help()
        exit()
    
    # Instanciate a new WatchManager (will be used to store watches).
    wm = pyinotify.WatchManager()
    # Associate this WatchManager with a Notifier (will be used to report and
    # process events).
    notifier = pyinotify.Notifier(wm, default_proc_fun=my_callback)
    # Add a new watch on /tmp for ALL_EVENTS.
    wm.add_watch(watched_folder, pyinotify.IN_CLOSE_WRITE, rec=True, auto_add=True)
    #wm.add_watch('/var/www', pyinotify.IN_CLOSE_WRITE, rec=True, auto_add=True)
    # Loop forever and handle events.
    notifier.loop()
