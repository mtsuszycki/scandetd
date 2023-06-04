# scandetd
Linux background daemon for detecting TCP scans.


  Scandetd is daemon which tries to recognize port scans. 
  If that happens daemon sends e-mail to root@localhost  (by default) 
  with following informations:
  
  - host  
  - number of connections made
  - port of the first connection and it's time
  - port of the last one and it's time
  - guessed type of scan (FIN, SYN) 
 
  compile: gcc scandetd.c -o scandetd
