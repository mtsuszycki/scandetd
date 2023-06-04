#include <pwd.h>
#include <grp.h>
#include "config.h"
#include "scandetd.h"

#include <sys/ioctl.h>
//#include <linux/if.h>
//#include <linux/if_ether.h>

#define VERSION "1.2.2"

#define SCAN_EXPIRE	120
#define PROT_TYPE(p)	(p)==TCP_TYPE?"":"UDP "

#define MAIL_TIME_LIMIT	60

struct tcppkt pkt;
struct udppkt udp_pkt;

int syslog_facility = LOG_FACILITY;
int dns_resolve;
int port_resolve;
int flood_det;
int log_details;
int detect_osfp = 1;

/* not used yet - mail flooding prevention */
struct mail_limit_t {
	time_t last;
	int disabled;
} mail_limit;

int osfp_options;

int mail_port = MAIL_PORT;
 
int count_threshold = COUNT_THRESHOLD;

struct config_group tcp_opt;
struct config_group udp_opt;

struct config_group *cfg[] = { &tcp_opt, &udp_opt };

volatile int alarm_flag;
time_t now;

struct host tcp_hosts[HOW_MANY];
struct host udp_hosts[HOW_MANY];
struct host osf_hosts[HOW_MANY];  /* for OS fingerprinting detection */
struct host *hosts[] = { tcp_hosts, udp_hosts, osf_hosts };

extern struct config_item config[];

static inline char *hostlookup(int i)
{
	static char buf[64];
	struct in_addr ia;
	struct hostent *he = 0;
	ia.s_addr = i;
	bzero(buf, sizeof buf);
	if(!dns_resolve) {
		strncpy(buf, inet_ntoa(*(struct in_addr *)&i) , sizeof buf - 1);
		return buf;
	}
	if ((he = gethostbyaddr((char *)&ia, sizeof ia, AF_INET)))
		strncpy(buf, he->h_name, sizeof buf - 1);
	else strncpy(buf, inet_ntoa(*(struct in_addr *)&i), sizeof buf - 1);
	return buf;
}

static inline char *servlookup(unsigned short port, enum prot_type p, int flag)
{
	struct servent *se;
   	static char buf[32];
        char *type[] = {"tcp", "udp"};
	snprintf(buf, sizeof buf, flag?"port %d":"%d", ntohs(port));
	if(!port_resolve) return buf;
	
   	se = getservbyport(port, type[p]);
   	if(se) snprintf(buf, sizeof buf, "%s", se->s_name);
	return buf;
}

void init()
{
    int i, j;
    now = time(NULL);
    for(j = 0; j < PROT_NR; j++)
    	for (i = 0; i < HOW_MANY; i++)
		hosts[j][i].t = now;
}

void pid_file(char *s)
{
	FILE *f;
	f = fopen(s, "w");
	if(!f) return;
	fprintf(f, "%d\n", getpid());
	fclose(f);
}

/*
 * If there is no empty slot then
 * choose the oldest one.
 */
struct host *allocate(int *p, unsigned int addr, enum prot_type j)
{
	int i;
	struct host *v = 0;
	struct host *cur = hosts[j];
	time_t tmp = cur[0].t;
	for(i = 0; i < HOW_MANY; i++){
		if (cur[i].t <= tmp) {
			tmp = cur[i].t;
			v = &cur[i];
		}
		if (cur[i].from == addr){
			*p = 1;
			return &cur[i];
		}
	}
	*p = 0;
	return v;
}

int __send_mail(char *buf, char *subject)
{
	static struct sockaddr_in sa;
	int s, i, mailport;
	char combuf[256];
	char *smtprelay;
	char *from = get_config_item("MailFrom")->value.svalue;
	char *to = get_config_item("RcptTo")->value.svalue;
	char *comm[] = {
		"HELO "	 	, get_config_item("HelloMsg")->value.svalue,
		"MAIL FROM: "	, from,
		 "RCPT TO:"	,  to,
		 "DATA"		, " ",
		 "From: "	, from,
		 "To: "		, to,
		 "Subject: "	, subject
	};
	i = fork();
	if (i < 0) return -1;
	if (i) return 0;

	mailport = *get_config_item("MailPort")->value.ivalue;
	smtprelay = get_config_item("SMTPRelay")->value.svalue;

	sa.sin_port = htons(mailport);
	sa.sin_family = AF_INET;

	if ((sa.sin_addr.s_addr = inet_addr(smtprelay)) == -1)
		exit (-1);
	
	bzero(&sa.sin_zero, 8);
	if ((s = socket(AF_INET,SOCK_STREAM,0)) < 0)
		exit (-1);
	
	if (connect(s,(struct sockaddr *) &sa, sizeof (struct sockaddr)) < 0)
		exit (-1);
	read(s, combuf, sizeof combuf);
	for (i = 0; i < sizeof comm/sizeof (char *) ; i += 2){
		snprintf(combuf, sizeof combuf, "%s%s\n",comm[i], comm[i+1]);
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

/* No more that 1 mail per minute is allowed */
int flood_prevent(char *msg)
{
	time_t now = time(0);
	if(now - mail_limit.last > MAIL_TIME_LIMIT) {
		mail_limit.disabled = 0;
		mail_limit.last = now;
	}	
	else if(!mail_limit.disabled) {
		mail_limit.disabled = 1;
		mail_limit.last = now;
		__send_mail(msg, "Mail notification disabled for a minute.");
	}
	return mail_limit.disabled;
}

struct fmt 
{
	char c;
	int *p;
	char *(*f)(int);
};

static char *protocol(int i)
{
	return i==UDP_TYPE?"UDP":"TCP";
}
	
static char *make_subject(struct host *h, enum prot_type p)
{
	struct fmt format[] = { 
		{ 's' , &h->from, hostlookup },
		{ 'd', &h->dst, hostlookup }, 
		{ 'p', (int *)&p, protocol }
	};
	static char buf[64];
	int i, n, size = sizeof format/sizeof (struct fmt);
	char *s = get_config_item("MailSubject")->value.svalue;
	char *ptr;
	int tmp;
		
	if(!s) return "Scan detected";
	bzero(buf, sizeof buf);
	for(n = 0; n < sizeof buf && *s; n++) {
		if(*s != '%') {
			buf[n] = *s++;
			continue;
		}
		if(!*(++s)) break;	
		for(i = 0; i < size; i++) { 
			if(format[i].c != *s) continue;
			ptr = format[i].f(*format[i].p);
			tmp = strlen(ptr);
			snprintf(buf + n, sizeof buf - n, "%s", ptr );
			n += tmp - 1;
			break;
		}			
		s++;			
	}
	return buf;
}


int send_mail(struct host *h, enum prot_type p)
{
	char buf[512], buf1[32], hostbuf[32];
	int low, high;
	char *type[] = { "SYN", "FIN stealth", "Null" };
	int i = 0;
	int c = 0;
	
	if(!(cfg[p]->flags & SEND_MAIL)) return 0;
	if(h->flags & MAIL_SENT) return 0;
	h->flags |= MAIL_SENT;
	if(!h->fin_count && !h->syn_count) i = 2;
	else if(h->fin_count > h->syn_count) i = 1;
	 
	low = ntohs(h->low_port);
	high = ntohs(h->hi_port);
	strncpy(buf1, ctime(&h->t), sizeof buf1);
	strncpy(hostbuf, hostlookup(h->dst), sizeof hostbuf);

	c = snprintf(buf, sizeof buf, 
		    "Possible %s port %s from %s to %s%s\n"
		    "I've counted %d connections.\n\n"
		    "First connection was made to %d port at %s"
		    "Last connection was made to %d port at %s\n",
		p==UDP_TYPE?"UDP":"TCP", h->flood>h->count/2?"flooding":"scanning",
		hostlookup(h->from), 
		hostbuf,
		h->flags&DST_CHANGED?" (and others),":",",
		h->count, low, ctime(&h->start), 
		high, buf1);
	if(p == TCP_TYPE) 
		snprintf(buf + c, (sizeof buf) - c,	
		    "Probably it was a %s scan" 
		    " (%d FIN flags and %d SYN flags)\r\n.\r\n",
		    type[i], h->fin_count, h->syn_count);
	else snprintf(buf + c, (sizeof buf) - c, "\r\n.\r\n");	
	if(flood_prevent(buf)) return 0;
	__send_mail(buf, make_subject(h,p));
	return 0;
}

static int addrport_match(int addr, int port, struct host_t *h)
{
	struct port_range *p;
	int ret = 0;
	if((addr & h->mask.s_addr) == h->ip.s_addr) {
		ret = 1;	
		for_each(p, h->ports) {
			ret = 0; 
			if(port >= p->start_port && port <= p->end_port) {
#ifdef DEBUG
			syslog(LOG_NOTICE, __FUNCTION__ ": %d (%d %d) returned 1", port, p->start_port, p->end_port);
#endif
				return 1;
			}	
		}	
	}
#ifdef DEBUG
	syslog(LOG_NOTICE, __FUNCTION__ ": returned %d", ret);
#endif
	return ret;
}

/*
 * Check if a given packet match src_addr:src_port -> dest_addr:dest_port
 * criteria as specified in a configuration file.
 */
static int packet_match(struct any_pkt *ap, struct list_head *h)
{
	struct config_host *p;
	int a, b;
#ifdef DEBUG
	syslog(LOG_NOTICE, "Entering " __FUNCTION__);
#endif	
	for_each(p, *h) {
		a = addrport_match(ap->ip.ip_src.s_addr, ntohs(ap->source), &p->src);
		if(a && !p->dst_mark) {
#ifdef DEBUG
			syslog(LOG_NOTICE, __FUNCTION__ ": returned 1 - src match");
#endif
			return 1;
		}	
		b = addrport_match(ap->ip.ip_dst.s_addr, ntohs(ap->dest), &p->dst);
		if(a && b) {
#ifdef DEBUG
			syslog(LOG_NOTICE, __FUNCTION__ ": returned 1 - dest match");
#endif
			return 1;
		}
	}
#ifdef DEBUG
	syslog(LOG_NOTICE, __FUNCTION__ ": returned 0");
#endif		
	return 0;
}

static inline int ignore_port(int *p, int lport)
{
	for(; p && *p; p++) 
		if(*p == lport) return 1;
#ifdef DEBUG
	syslog(LOG_NOTICE, __FUNCTION__ ": returned 0");
#endif		
	return 0;
}

static void dolog_details(struct any_pkt *ap, enum prot_type p)
{
	char s[32], port[16];
	snprintf(s, sizeof s,  hostlookup(ap->ip.ip_dst.s_addr));
	snprintf(port, sizeof port, servlookup(ap->dest, p, 0));

	syslog(LOG_NOTICE, "%s %s(%s) -> %s(%s)",
		p==UDP_TYPE?"UDP":"TCP",
		hostlookup(ap->ip.ip_src.s_addr),
		servlookup(ap->source, p, 0),
		s,
		port
		);
}	
	
static void dolog(struct any_pkt *ap, enum prot_type p)
{
	if(packet_match(ap, &cfg[p]->host_log_ign))
		 return;

	if(ignore_port(cfg[p]->port_log_ignore, ntohs(ap->dest))) return;
	if(log_details) {
		dolog_details(ap, p);
		return;
	}	
	if(dns_resolve)	
		syslog(LOG_NOTICE,"%s%s connection attempt from %s (%s)",
			PROT_TYPE(p),
			servlookup(ap->dest, p, 1),
			hostlookup(ap->ip.ip_src.s_addr),
			inet_ntoa(ap->ip.ip_src));
	else
		syslog(LOG_NOTICE,"%s%s connection attempt from %s",
			PROT_TYPE(p),
			servlookup(ap->dest, p, 1),
			inet_ntoa(ap->ip.ip_src)
			);
}	

void log_scan(struct host *h, enum prot_type p)
{
	char buf[32];
	if(!(cfg[p]->flags & LOG_SCAN)) return;
	if(h->flags & SCAN_LOGGED) return;
	h->flags |= SCAN_LOGGED;
	strncpy(buf, hostlookup(h->dst), sizeof buf);
	syslog(LOG_NOTICE,"Possible %sport %s from %s to %s%s",
			PROT_TYPE(p),
			h->flood>h->count/2?"flood":"scan",
			hostlookup(h->from),
			buf,
			h->flags&DST_CHANGED?" (and others)":""
		);
}

static inline int was_scan(struct host *h, enum prot_type p)
{
	return !(h->count < count_threshold);
}

void update_flags(struct host *h, enum prot_type prot, struct tcphdr *tcp)
{
	if(prot != TCP_TYPE) return;
	h->syn_count += (tcp->th_flags) & TH_SYN ? 1:0; 		
	h->fin_count += (tcp->th_flags) & TH_FIN ? 1:0; 
}			

void packet_init(struct host *h, struct any_pkt *ap, struct tcphdr *tcp, enum prot_type prot)
{
	h->syn_count = h->fin_count = 0;
	h->from = ap->ip.ip_src.s_addr;
	h->dst = ap->ip.ip_dst.s_addr;
	h->low_port = ap->dest; 
	h->hi_port = ap->dest;
	h->prev_port = ap->dest;
	h->count = 1;
	h->start = now;
	h->t = now;
	update_flags(h, prot, tcp);
}

void action(struct any_pkt *ap, struct tcphdr *tcp, enum prot_type prot)
{
	int was = 0;
	struct host *h;

	if(cfg[prot]->flags & LOG_CONN && (prot == UDP_TYPE || 
			(prot == TCP_TYPE && tcp->th_flags == TH_SYN))) 
		dolog(ap, prot);
	if(packet_match(ap, &cfg[prot]->host_scan_ign)) return;
	if(ignore_port(cfg[prot]->port_scan_ignore, ntohs(ap->dest))) return;

	h = allocate(&was, ap->ip.ip_src.s_addr, prot);
	if(!h) {
		syslog(LOG_ERR, " internal error, cannot allocate memory");
		exit(1);
	}
	if (was) goto UPDATE_DATA;
#ifdef DEBUG
	syslog(LOG_NOTICE, "new host %s", inet_ntoa(ap->ip.ip_src));
#endif
	/*
 	 * Current host is going to be deleted. Check if a scan 
	 * warning should be sent.
 	 */
	if(was_scan(h, prot)) {
		send_mail(h, prot);
		log_scan(h, prot);
	}
	packet_init(h, ap, tcp, prot);
	return;
UPDATE_DATA:	
	if (now - h->t <= SEC) {
		if(!flood_det && h->prev_port == ap->dest) {
			h->t = now;
			return;
		}
		if(ap->ip.ip_dst.s_addr != h->dst) 
			h->flags |= DST_CHANGED;
//h->start = now;
		h->count++;
#ifdef DEBUG
syslog(LOG_NOTICE, "update host %s %d", inet_ntoa(ap->ip.ip_src), h->count);
#endif
		h->hi_port = ap->dest;
		if(h->prev_port == ap->dest) h->flood++;
		h->prev_port = ap->dest;
		update_flags(h, prot, tcp);
	}
	else if(!was_scan(h, prot) && now - h->t >= SCAN_EXPIRE) {
		bzero(h, sizeof *h);
		return;
	}
	h->t = now;
}

void search_scan()
{
	int i, p;
	time_t now = time(0);
	struct host *h;
	for(p = 0; p < PROT_NR; p++)
		for(i = 0; i < HOW_MANY; i++){
			h = &hosts[p][i];
#ifdef DEBUG
syslog(LOG_NOTICE, "checking for scan %d", h->from);
#endif
			if((now - h->t) < SCAN_TIMEOUT || !was_scan(h, p))
				continue;
			log_scan(h, p);
			send_mail(h, p);
			h->count = 0;
		}
}

void alarm_handler(int sig)
{
	alarm_flag = 1;
	alarm(ALARM_TIMEOUT);
}

void hup_handler(int sig)
{
	syslog(LOG_NOTICE, "SIGHUP received. Reloading configuration.");
	clear_conf(&tcp_opt);
	clear_conf(&udp_opt);
	load_defaults();
	read_conf();
#ifdef DEBUG
	show_conf();
#endif	
}

#define TH_XX	0x40
#define TH_YY	0x80

#define OS_FP		2

#define NMAP_SX		0x1
#define NMAP_NULL 	0x2
#define NMAP_FSPU 	0x4
#define NMAP_FPU	0x8
#define QUESO_F 	0x10
#define QUESO_FS 	0x20
#define QUESO_P 	0x40
#define QUESO_SXY	0x80

struct probe_flags {
	unsigned int id;
	u_int8_t or_flags;
	tcp_seq seq;
	tcp_seq ack;
	char *s;
};

struct probe_flags fp_probe[] = {
	{ NMAP_SX, TH_SYN|TH_XX, 0, 0, "sx" },
	{ NMAP_NULL, 0, 0, 0, "null" },
	{ NMAP_FSPU, TH_FIN|TH_SYN|TH_PUSH|TH_URG, 0, 0, "fspu" },
	{ NMAP_FPU, TH_FIN|TH_PUSH|TH_URG, 0, 0, "fpu" },
	{ QUESO_F, TH_FIN, 0, 0, "f" },
	{ QUESO_FS, TH_FIN|TH_SYN, 0, 0, "fs" },
	{ QUESO_P, TH_PUSH, 0, 0, "p" },
	{ QUESO_SXY, TH_SYN|TH_XX|TH_YY, 0, 0, "sxy" }
};	

static void osfp_mail(struct host *h, int count, char *s)
{
	char buf[512], pkts[64];
	int i, size, c = 0;
	size = sizeof(fp_probe)/sizeof(struct probe_flags);
	for(i = 0; i < size; i++) {
		if(!(h->osfp_flags & fp_probe[i].id)) continue;
		c += snprintf(pkts + c, sizeof pkts - c,
			"%s,", fp_probe[i].s);
//printf(__FUNCTION__ ": %s\n", fp_probe[i].s);
	}
	snprintf(buf, sizeof buf, 
		"Possible %s OS fingerprinting probe from %s\n"
		"%d packets were detected with following TCP flags:\n"
		"%s\nFirst packet arrived at %s\n\r\n.\r\n",
		s, hostlookup(h->from),count, pkts, ctime(&h->start)
		);
	if(flood_prevent(buf)) return;
	__send_mail(buf, "OS fingerprinting probe");
}	

/*
 * If we have 3 suspicous packets then it is probably OS probe. 
 * Lower 4 bits in host->osfp_flags are related to
 * queso packets. Next 4 bits  are for nmap.
 * If count == 3 and tcp flags in packets where not specific
 * to nmap nor queso then os probe is "unknown" (return 3)
 */
static int was_probe(int f, int *count)
{
	int i, size = sizeof fp_probe/sizeof(struct probe_flags);
	int found = 0;
	*count = 0;
	for(i = 0; i < size; i++) {
//	        *count += (f & (1 << i))?1:0;
		*count += (f & fp_probe[i].id)?1:0;
//syslog(LOG_NOTICE, "flag %d : %d", f&(1<<i), i);
		if(*count == 3) found = 1;		 
	}		 
	if(!found) return 0;
	if(f & 0xf && f < 0xf) return 1;
	if(f & 0xf0 && f >= 0xf) return 2;
	return 3;
}

char *osfp_type[] = { "nmap", "queso", "unknown" };

static  void probe_check(struct tcppkt *pkt)
{
	int i, was, found = 0;
	struct host *h;
	int t, count;
	int s = sizeof(fp_probe)/sizeof(struct probe_flags);
	/* is there something interesting? */
	for(i = 0; i < s; i++) {
		if(fp_probe[i].or_flags != pkt->tcp.th_flags) continue;
//syslog(LOG_NOTICE, __FUNCTION__ "%d: %s found", i, fp_probe[i].s);
		found = 1;
		break;
	}
	if(!found) return;
	h = allocate(&was, pkt->ip.ip_src.s_addr, OS_FP);
	if(!was) {
		h->from = pkt->ip.ip_src.s_addr;
		h->osfp_flags = 0;
		h->start = now;
	}
	if(h->osfp_flags && now - h->t > 2*SEC) return;
	h->t = now;
	h->osfp_flags |= fp_probe[i].id;
	t = was_probe(h->osfp_flags, &count);
	if(!t) return;
	if(osfp_options & SEND_MAIL && !(h->flags & MAIL_SENT)) {
		h->flags |= MAIL_SENT;
		osfp_mail(h, count, osfp_type[t-1]);	
	}	
//syslog(LOG_NOTICE, "id %d %s %d", fp_probe[i].id, hostlookup(h->from), h->osfp_flags);
	if(h->flags & SCAN_LOGGED || !(osfp_options & LOG_SCAN)) return;
	h->flags |= SCAN_LOGGED;
	syslog(LOG_NOTICE, "Possible %s OS probe from %s",
		osfp_type[t-1], hostlookup(h->from)
		);
	return;	
}	

int main(int argc, char **argv)
{
	int s, su, err = 0;
	gid_t grp[2];
	char *i;
	struct sigaction sa;
	struct passwd *p;
 	fd_set read_fds;
	
	if (geteuid())
		errx(1, "This program requires root priviledges.");
	sa.sa_handler = alarm_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	
	INIT_LIST_HEAD(&udp_opt.host_scan_ign);	
	INIT_LIST_HEAD(&udp_opt.host_log_ign);	
	INIT_LIST_HEAD(&tcp_opt.host_scan_ign);	
	INIT_LIST_HEAD(&tcp_opt.host_log_ign);	
	
	load_defaults();
	read_conf();
	if(argc == 2) {
		if(!strncmp(argv[1], "-v", 2)) show_conf();
		else if(!strncmp(argv[1], "-s", 2)) {
			show_conf();
			exit(0);
		}
	}
	i = get_config_item("RunAsUser")->value.svalue;
	p = getpwnam(i);
	
	if ((s = socket(AF_INET, SOCK_RAW, 6)) == -1)
		errx(1, "Cannot open TCP raw socket. Exiting.");
	if ((su = socket(AF_INET, SOCK_RAW, 17)) == -1)
		errx(1, "Cannot open UDP raw socket. Exiting.");
	fcntl(s, F_SETFL, O_NONBLOCK);
	fcntl(su, F_SETFL, O_NONBLOCK);
	openlog("scandetd", LOG_NDELAY, syslog_facility);

	daemon(1, 1);
	pid_file(PID_FILE);
	
	/* Drop root priviledges */	
	if(!p) {
		syslog(LOG_ERR, "%s doesn't exists. Exiting.", i);
		exit(1);
	}  
	grp[0] = grp[1] = p->pw_gid;
	err = setgroups(1, grp);
	err = setgid(p->pw_gid);
	err = setuid(p->pw_uid);
	if(err == -1) {
		syslog(LOG_ERR, "Cannot drop root priviledges. Exiting.");
		exit(1);
	}
	init();

	syslog(LOG_NOTICE,"scandetd ver. " VERSION "  started and ready");

	FD_ZERO(&read_fds);
	sigaction(SIGALRM, &sa, 0);
	signal(SIGHUP, hup_handler);
	alarm(ALARM_TIMEOUT);
	
	/* to avoid zombies */
	signal(SIGCHLD,SIG_IGN);		

	for(;;) {
		int len, ret;
		FD_SET(su, &read_fds);
		FD_SET(s, &read_fds);		
		ret = select(su+1, &read_fds, 0, 0, 0);
		if(alarm_flag) {
			alarm_flag = 0;
			search_scan();
		}
		/*
		 * Don't process the data if select was interrupted
		 * by alarm().
		 */
		if(ret == -1 && errno == EINTR) 
			continue;
		now = time(NULL);
		if(FD_ISSET(su, &read_fds)) 
			if(read(su, (struct udppkt*) &udp_pkt, sizeof udp_pkt) >= sizeof udp_pkt)
				action((struct any_pkt *)&udp_pkt, 0, UDP_TYPE);

		if(!FD_ISSET(s, &read_fds)) continue;
		len = read(s, (struct tcppkt*) &pkt, sizeof pkt);

		if (len < sizeof pkt) continue;	
		if(osfp_options) probe_check(&pkt);

		if (pkt.tcp.th_flags < 3)
			action((struct any_pkt *) &pkt, &pkt.tcp, TCP_TYPE);
	}
}
 
