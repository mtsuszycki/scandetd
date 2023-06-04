/*
 * Scandeted 1.0
 *
 * Scandetd is daemon which tries to recognize port scans. 
 * If that happens daemon sends e-mail to root@localhost  (by default) 
 * with following informations:
 * 
 * - host  
 * - number of connections made
 * - port of the first connection and it's time
 * - port of the last one and it's time
 * - guessed type of scan (FIN, SYN) 
 *
 * compile: gcc scandetd.c -o scandetd
 *
 *
 * author: Michal Suszycki	mike@wizard.ae.krakow.pl
 *
 * You can change few define's and variables below this comment to tune
 * scandetd to your needs.
 * 
 * This code was based on IpLogger Package by Mike Edulla (medulla@infosoc.com)
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
 
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netdb.h>
#include <time.h>
#include <signal.h>
#include <string.h>


#if (linux)
#define __FAVOR_BSD
#endif

#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

extern int errno;


/* 
 * how many hosts should I remember. If your server is heavily loaded it's
 * good idea to increase this number a little bit
 */
#define HOW_MANY 6

/*
 * how many connections should I recognize as scanning?
 */
#define SCAN 20

/* 
 * uncomment this to enable printing to log files scan warnings (using syslogd)
 */
//#define DOSYSLOG

/* 
 * uncoment this if you want to log every connection attempt (using syslogd)
 */
//#define LOGCON

/* 
 *  here you can define special port you want to ignore:
 *  if 'scanning' started and ended on the same port and this port is equal
 *  to NOPORT then 'scanning'  will be ignored. If you  notice for example that
 *  your server get a lot of fast connections (from one host) to www port you 
 *  can define NOPORT to 80 so there will be no false warnings 
 */ 
#define NOPORT 80

/* 
 * If next connection arrived right after the previous one we have to count it.
 * Default time is 1 second.
 */
#define SEC 1

/* 
 * We use this port for sending mail 
 */
#define MAILPORT 25

/* 
 * we send mail to <user@host>: 
 */
char *mail_to = "<root@localhost>";

/* 
 * IP of the machine which sends our mail 
 */
char *mail_host = "127.0.0.1";

/* 
 * mail will be send from host: 
 */
char *from_host = "localhost";


/* ------------------- end of user's configuration  ----------------------- */

#ifndef NOFILE
#define NOFILE 1024
#endif


char *hostlookup(int i)
{
	static char buff[256];
	struct in_addr ia;
	struct hostent *he;
	ia.s_addr = i;
	
	if (!(he = gethostbyaddr((char *)&ia, sizeof ia, AF_INET)))
		strncpy(buff,inet_ntoa(ia),sizeof buff);
	else
		strncpy(buff,he->h_name,sizeof buff);
	return buff;
}

char *servlookup(unsigned short port)
{
	struct servent *se;
   	static char buff[256];
      
   	se=getservbyport(port, "tcp");
   		if(se == NULL) sprintf(buff, "port %d", ntohs(port));
       		else sprintf(buff, "%s", se->s_name);
	return buff;
}

struct ippkt{
	struct ip ip;
	struct tcphdr tcp;
} pkt;

struct host{
	unsigned int from;
	time_t t;
	time_t start;
	unsigned short low_port;
	unsigned short hi_port;
	unsigned int count, fin_count, syn_count;
} hosts[HOW_MANY];

void be_a_daemon()
{
	int fd, f;
	
	if (getppid() != 1){
		signal(SIGTTOU,SIG_IGN);
		signal(SIGTTIN,SIG_IGN);
		signal(SIGTSTP,SIG_IGN);
		f = fork();
		if (f < 0)
			exit(-1);
		
		if (f > 0)
			 exit (0);
	/* child process */		
	setpgid(0,0);
	for (fd = 0 ; fd < NOFILE; fd++) close(fd);
	chdir("/");
	umask(0);
	return;
	}
}	

void init()
{
    int i;
    time_t now;
    now = time(NULL);
    for (i = 0; i < HOW_MANY; i++)
	hosts[i].t = now;
}

int allocate(int *p, unsigned int addr)
{
	int i, v = 0;
	time_t tmp = hosts[0].t;
	for( i = 0; i < HOW_MANY; i++){
		if (hosts[i].t <= tmp) {
			tmp = hosts[i].t;
			v = i;
		}
		if (hosts[i].from == addr){
			*p = 1;
			return i;
		}
	}
	*p = 0;
	return v;
}

/* for debug */ 
void show(int a)
{
	int i;
	
	for (i = 0; i < HOW_MANY; i++){
		printf("Host %s, time %ld, count=%d, l=%d,",
			hostlookup(hosts[i].from),hosts[i].t, hosts[i].count,
			ntohs(hosts[i].low_port));
		printf("hi = %d\n",ntohs(hosts[i].hi_port));
	}		
	exit (0);
}

void no_zombie(int i)
{
	wait(NULL);
}

int send_mail(struct host *bad)
{
	static struct sockaddr_in sa;
	int s, i, low, high;
	char buf[1024], combuf[256];
	
	char *comm[] = { "HELO ", 			from_host,
			 "MAIL FROM: SCANDETD@",	from_host,
			 "RCPT TO:"		,	mail_to,
			 "DATA"			,	" "
			};
	i = fork();
	
	if (i < 0) return -1;
	if (!i) return 0;
	
	low = ntohs(bad->low_port);
	high = ntohs(bad->hi_port);
	strncpy(combuf,ctime(&bad->t),sizeof combuf);
	sprintf(buf,"Possible port scanning from %s,\n"
		    "I've counted %d connections.\n\n"
		    "First connection was made to %d port at %s"
		    "Last connection was made to %d port at %s\n"
		    "Probably it was %s" 
		    " (%d FIN flags and %d SYN flags)\r\n.\r\n",
		hostlookup(bad->from),bad->count, low, ctime(&bad->start), 
		high,  combuf,
		bad->fin_count>bad->syn_count?"FIN stealth scan":"SYN scan",
		bad->fin_count, bad->syn_count);
					
	sa.sin_port = htons(MAILPORT);
	sa.sin_family = AF_INET;
	if ((sa.sin_addr.s_addr = inet_addr(mail_host)) == -1)
		exit (-1);
	
	bzero(&sa.sin_zero, 8);
	if ((s = socket(AF_INET,SOCK_STREAM,0)) < 0)
		exit (-1);
	
	if (connect(s,(struct sockaddr *) &sa, sizeof (struct sockaddr)) < 0)
		exit (-1);
	
	for (i = 0; i < 8 ; i += 2){
		sprintf(combuf,"%s%s\n",comm[i],comm[i+1]);
		if (write(s,combuf,strlen(combuf)) < 0 ){
			close(s);
			exit(-1);
		}
		sleep(1);
	}
	if (write(s,buf,strlen(buf)) < 0) exit(-1);
	sleep(1);
	if (write(s,"QUIT\n",5) < 0) exit (-1);
	close(s);
	exit(0);
}

void action(struct ippkt *pkt)
{
	int i, was = 0;
	time_t now;
	now = time(NULL);

#ifdef LOGCON
	syslog(LOG_NOTICE,"%s connecion attempt from %s",
		servlookup(pkt->tcp.th_dport),
		hostlookup(pkt->ip.ip_src.s_addr));
#endif	
	i = allocate(&was,pkt->ip.ip_src.s_addr);
			
	if (!was){
		if (hosts[i].count >= SCAN
#ifdef NOPORT				
 		&& hosts[i].low_port != htons(NOPORT)
		&& hosts[i].hi_port  != htons(NOPORT)
#endif
						){
			send_mail(&hosts[i]);
#ifdef DOSYSLOG			
			syslog(LOG_NOTICE,"Possible port scanning from %s",
				hostlookup(hosts[i].from));
#endif
		}
		hosts[i].from = pkt->ip.ip_src.s_addr;
		hosts[i].low_port = pkt->tcp.th_dport; 
		hosts[i].hi_port = pkt->tcp.th_dport;
		hosts[i].count = 1;
		hosts[i].syn_count = (pkt->tcp.th_flags) & TH_SYN ? 1:0;
		hosts[i].fin_count = (pkt->tcp.th_flags) & 1 ? 1:0;
		hosts[i].start = now;
	}
	/* if the connection was right after the previous one we must count it */
	if (now - SEC <= hosts[i].t){
		hosts[i].count++;
		hosts[i].hi_port = pkt->tcp.th_dport;
		hosts[i].syn_count += (pkt->tcp.th_flags) & TH_SYN ? 1:0; 		
		hosts[i].fin_count += (pkt->tcp.th_flags) & 1 ? 1:0; 		
	}
	hosts[i].t = now;
}

void main(int argc, char **argv)
{
	int s;
	
	if (geteuid()){
		printf("This program requires root priviledges.\n");
		exit(0);
	}
#if (freebsd)
	printf("dupa\n");
#endif
	be_a_daemon();
	init();
	if  ((s = socket(AF_INET, SOCK_RAW, 6)) == -1)
		exit(0);
	
		

#ifdef DOSYSLOG
	openlog("scandetd", 0, LOG_LOCAL2);
	syslog(LOG_NOTICE,"scandetd started and ready");
#endif
//	signal(SIGINT,show);
	
/* to avoid zombies */
	signal(SIGCHLD,no_zombie);

	while(1){
		read(s, (struct ippkt*) &pkt, sizeof(pkt));
		/* TH_FIN or TH_SYN is set and TH_ACK is zero */
		if (pkt.tcp.th_flags < 3 && !(pkt.tcp.th_flags & TH_ACK)) 
			action(&pkt);
	}
}

