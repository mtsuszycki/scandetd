# scandetd
Linux background daemon for detecting TCP scans. Can be used as a simple TCP/UDP connection logger

Scandeted 1.2.0
 
Scandetd is a daemon which tries to recognize TCP and UDP port scans 
and OS fingerprinting probes. Program also could be used as a TCP/UDP
connection logger.
It knows Nmap and Queso probes and tries to recognize them.
If it encounters port scan or OS probe  it is able to send an e-mail 
with following informations:
  
  - scanning host  
  - number of connections made
  - port of the first connection and it's time
  - port of the last one and it's time
  - guessed type of scan (SYN, FIN, NULL) - if it was a TCP scan 
  - TCP flags set in packets (if OS probe)

In the configuration file you can specify all necessary options.
Take a look at sample configuration. It should be self explanatory. 
If you want running scandetd to read configuration again then send him
a HUP signal.

Command line arguments:
-v	be verbose - show current configuration at start up.
-s 	do _not_ start the daemon - just show parsed config file.

It was written long time ago, most likely I would have written things differently now,
for example sending emails via fork() and making TCP connection to 25 and sending
text "MAIL FROM" etc. is a bit rough.

----------------------------------------------------------------------
INSTALL
 
Type 'make' to compile
To install type 'make install' 
/usr/sbin/ is default directory for executable, and /etc for config file.
It can be changed in a Makefile.

Scandetd was tested only under Linux and probably it works only under Linux.
This code is free.
It is released under GPL licence - please read COPYING file.

author: Mike Suszycki	
This code was inspired and based on IpLogger Package 
by Mike Edulla (medulla@infosoc.com) 

CONFIG FILE OPTIONS (see scandetd.conf)
```
# Sample configuration file for scandetd 1.2.0
# Please send comments/suggestions/flames to mike@wizard.ae.krakow.pl
# Please edit this file. This is only an example.

# It is much more better not to run as root

RunAsUser nobody

# Syslog facility (without "LOG_" prefix) . See openlog(3) for details.
# If you change this option then you _must_ restart the daemon
# (sending HUP won't work).

SyslogFacility local2

# ----------------------------------------------------------------------
# Scandetd could be used just as a simple TCP and UDP connection logger.
# Two options below applies to both TCP and UDP protocols:

# DNS lookups just make things slower

DNSResolve	no


# Set to 'yes' if you want scandetd to try to translate
# port numbers to names.

PortResolve 	no


# Use detailed log format: src_addr (src_port) -> dst_addr (dst_port)

LogDetails	no

### TCP options: ###
#
# Set to 'yes' if you want scandetd to log all incoming
# TCP connections (via syslog)

LogConnections  no


# Do not log TCP connections that are made to following ports 

PortLogIgnore 80 110


# Do not log TCP connections that matches following criteria.
# Format:
# src_ip/mask:src_port -> dst_ip/mask:dst_port
# Ports are separated by commas.
# Port ranges can be given as "low_port-high_port" (inclusive)
# If "->" is ommited then expression describes source ip and source ports (!).
# Do _not_ use spaces inside IP/mask:port_spec                                       

HostLogIgnore 127.0.0.0/8
HostLogIgnore 192.168.1.0/24:1024-65535 -> 192.168.1.1:1-1024,3306


### UDP options: ###
#
# Set to 'yes' if you want scandetd to log all incoming
# UDP connections (via syslog)

UdpLogConnections  no


# Do not log UDP connections that are made to following ports 

UdpPortLogIgnore 517 518

# Do not log UDP packets that matches following criteria:

UdpHostLogIgnore 127.0.0.1/8
UdpHostLogIgnore 0/0:1024-65535 -> 0/0:53


### OS Fingerprinting probes ###
#
# Scandetd may try to recognize OS fingerprinting probes sent
# by nmap or queso.
# Do you want to log warning via syslog?

LogOSFP		yes

# should I also send email with warning?

OSFPSendMail	yes

# ------------------------------------------------------------
# Probably the most important part.
# By carefully changing values below you prevent yourself
# from false scan warnings.

# Do we want to increase internal counter if rapid connections
# are made to the same destination port?

FloodDetection yes

# Limit for TCP protocol

# Whenever connection is made to one of the following ports then it
# is skipped and will never increase internal counters.
# Please notice that this rule is redundant because it can
# be replaced by HostScanIgnore (ie. 0/0 -> 0/0:80,110)

PortScanIgnore 80 110


# and UDP

UdpPortScanIgnore 517 518


# Rules below describes which packets should be omited

HostScanIgnore 127.0.0.1/8 
HostScanIgnore 0/0 -> 0/0:137
HostScanIgnore 192.168.1.0/24:1-1024 -> 192.168.1.1:1024-65535

UdpHostScanIgnore 0/0:53 -> 0/0
UdpHostScanIgnore 127.0.0.1/24 192.168.1.0/24 -> 192.168.1.1:53,111
UdpHostScanIgnore 0/0 -> 0/0:137


# How many rapid connections should be treated as port scan?

CountThreshold	40

# ------------------------------------------------------------
# OK. Now it is time to tell scandetd how to behave
# when port scan is detected.

# Do you want to see a message in your logs (via syslog) about
# possible TCP port scan/flood?

LogScans        yes

# What about UDP scan/flood?

UdpLogScans	yes


# Do you want scandetd to send an email (for TCP scans)?

SendEmail 	yes


# Do you also want to have an email with UDP scan warning?

UdpSendEmail	yes


# Scandetd needs few information to properly send an email.
# Envelope's "From:"

MailFrom  Scandetd@localhost


# Mail goes to:

RcptTo 	root@localhost

# Mail subject. Does not apply to OS fingerpring emails.
# If you use spaces then string must be
# enclosed with quotes).
# %p - protocol, %s - source IP, %d - destination IP

MailSubject	"%p scan from %s"

# *IP* (not name!) of the host that is able to send our message

SMTPrelay 127.0.0.1


# Standard SMTP port

MailPort 25

# Argument for HELO command when sending email.
# This should be the name of your host where scandetd is running.

HelloMsg "localhost"


# that's it. 
```
