# monitoring-tool

Requirements:-

Before running the daemon script,
1. Install paramiko.
$ pip install paramiko
2. Make sure passwordless ssh is configured between source and destination.

To stop the daemon,
1. Kill the process associated with it.
2. Remove the lock file containing the PID.
$ rm /tmp/monitor.pid

Log file: /tmp/monitor_<hostIpAddress>.log
eg. /tmp/montor_192.168.1.100.log
