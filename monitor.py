#!/usr/bin/python

import sys
import time
import socket
import paramiko
import time
import os
import signal
import atexit
import mmap

# Function to daemonize the script.
def daemonize(pidfile, stdin='/dev/null', stdout='/dev/null',stderr='/dev/null'):
  if os.path.exists(pidfile):
    print 'Already Running'
    sys.exit()
  try:
    if os.fork() > 0:
      raise SystemExit(0)
  except OSError:
    raise RuntimeError('fork 1 failed')

  os.umask(0)
  os.setsid()

  try:
    if os.fork() > 0:
      raise SystemExit(0)
  except OSError:
    raise RuntimeError('fork 2 failed')

  with open(stdin, 'rb', 0) as f:
    os.dup2(f.fileno(), sys.stdin.fileno())
  with open(stdout, 'ab', 0) as f:
    os.dup2(f.fileno(), sys.stdout.fileno())
  with open(stderr, 'ab', 0) as f:
    os.dup2(f.fileno(), sys.stderr.fileno())

  # Write the pidfile PID
  with open(pidfile, 'w') as f:
    f.write(str(os.getpid()))

  atexit.register(lambda: os.remove(pidfile))

  def sigterm_handler(signo, frame):
    raise SystemExit(1)

  signal.signal(signal.SIGTERM, sigterm_handler)

# Function to get the previous process count and /var usage.
def get_last_count():
  with open(log_file, 'r') as logfile:
    m = mmap.mmap(logfile.fileno(), 0, prot=mmap.PROT_READ)
    num = 0
    last_process = ''
    pos = m.rfind('_Running')
    print(pos)
    if pos != -1:
      m.seek(pos)
      while 1:
        line = m.readline()
        if not line:
          break
        else:
          if num == 1:
            last_process = line
          elif num == 7:
            last_var = line
            last_var_usage = int(last_var.split("%")[0])
        num += 1
      
  if last_process != '':
    last_process_count = int(last_process.split()[0])
    return last_process_count, last_var_usage

#Function to collect the details and write to log file.
def collect_info(hostIP,interval,commands,user):
  syslog_file = '/tmp/syslog_msgs'
  remote_syslog_file = '/var/log/messages'
  syslog_pos = 0
  last_process_count = 0
  last_var_usage = 0
  number_of_runs = 0
  while 1:
    try:
      p = paramiko.SSHClient()
      p.set_missing_host_key_policy(paramiko.AutoAddPolicy())
      p.connect(hostIP, port=22, username=user)
    except:
      print "Could not connect to IP " + hostIP
      sys.exit()
    finally:
      p.close()

    os.system("scp "+hostIP+":"+remote_syslog_file+" "+syslog_file)

    print(log_file)
    if number_of_runs != 0:
      last_process_count,last_var_usage = get_last_count()

    try:
      p = paramiko.SSHClient()
      p.set_missing_host_key_policy(paramiko.AutoAddPolicy())
      p.connect(hostIP, port=22, username=user)
    except paramiko.AuthenticationException:
      print "Auth failed"
      sys.exit()
    except:
      print "Could not connect" 
      sys.exit()

    d = os.popen("date").read()
    pid = os.popen("cat " + pid_file).read()
    fh = open(log_file,"a+")
    fh.write("Run number: " + str(number_of_runs + 1) + " :: " + pid + "_Running the monitoring script on " + d)
    fh.close()
    for cmd in range(0,len(commands)):
      stdin, stdout, stderr = p.exec_command(commands[cmd])
      opt = stdout.readlines()
      opt = "".join(opt)
      if cmd == 0:
        proc_diff = int(opt) - last_process_count
        if proc_diff >= 0:
          opt = opt.rstrip("\n") + " +" + str(proc_diff) + "\n"
        else:
          opt = opt.rstrip("\n") + " " + str(proc_diff) + "\n"
    
      elif cmd == 2:
        var_diff = int(opt.split("%")[0]) - last_var_usage
        if var_diff >= 0:
          opt = opt.rstrip("\n") + " +" + str(var_diff) + "%\n"
        else:
          opt = opt.rstrip("\n") + " " + str(var_diff) + "%\n"
 
      fn = open(log_file,"a")
      fn.write(opt)
    with open(syslog_file,mode='r') as sys_log:
      with open(log_file,"a") as log:
        n = mmap.mmap(sys_log.fileno(), 0, prot=mmap.PROT_READ)
        n.seek(syslog_pos)
        while 1:
          line = n.readline()
          if not line:
            break
          else:
            if 'ERROR' in line.upper():
              fn.write(line)
      syslog_pos = n.tell()
    fn.write("\n")  
    fn.close()

    time.sleep(interval)
    number_of_runs += 1

# Function to display the script usage.
def usage():
  print 'Usage:'
  print '%s <hostIpAddress> <interval>' % (sys.argv[0])
  print '<hostIpAddress> IP address to connect to.'
  print '<interval> in seconds. A positive number.'
  sys.exit()

### Main body

if len(sys.argv) != 3:
  usage()

hostIP = sys.argv[1]
interval = sys.argv[2]

log_file = "/tmp/monitor_"+hostIP+".log"
pid_file = '/tmp/monitor.pid'

## Check IP address validity
try:
  socket.inet_pton(socket.AF_INET, hostIP)
except:
  print 'ERROR: IP address provided is invalid'
  usage()

## Check valid interval
try:
  interval = int(interval)
except ValueError:
  print 'ERROR: Interval provided is invalid'
  usage()
  
if interval <= 0:
  print("Minimum interval should be 1 sec.")
  usage()

user = os.popen("whoami").read().rstrip("\n")
commands = ["ps aux | wc -l","ps aux | awk '{print $2, $4, $11}' | sort -k2rn | head -5","df -h /var | tail -1 | awk '{print $5}'"]

try:
  daemonize(pid_file, stdout=log_file,stderr=log_file)
except RuntimeError:
  print 'Failed to run as daemon'
  sys.exit()

collect_info(hostIP,interval,commands,user)
