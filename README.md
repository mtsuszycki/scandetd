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


