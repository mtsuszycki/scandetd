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
#include <ctype.h>
#include <err.h>

#include "config.h"
#include "scandetd.h"

#if (linux)
#define __FAVOR_BSD
#endif

#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

extern int errno;
extern int syslog_facility;
extern int flood_det;
extern int log_details;
extern int osfp_options;

char *log_fac[] = {
	"kern", 0, "mail", "daemon", "auth", "syslog", "lpr", "news",
	"uucp", "cron", "authpriv", "ftp", "local"
};

int valid_sep(char c)
{
	return c == '=' || c == ' ' || c == '\t' || c == '\"';
#define ANNOYING_MC "\""
}

int log_facility(char *s, union value_t *v, int f)
{
	int i, z, d, len;
	z = sizeof log_fac/sizeof(char *);
	for(i = 0; i < z; i++) { 
		if(!log_fac[i]) continue;
		len = strlen(log_fac[i]);
		if(!strncasecmp(log_fac[i], s, len))
			goto FOUND;
	}		
	return -1;
FOUND:
	/* facility isn't 'local' */
	if(i < z - 1) {
		*v->ivalue = i<<3;
		return 0;
	}
	if(!s[5]) return -1;
	sscanf(s+5, "%d", &d);
	if(d < 0 && d > 7) return -1;
	*v->ivalue = (12+4+d)<<3;
	return 0;
}
	

int boolean(char *s, union value_t *v, int f) 
{ 
	int ret = 1;
	ret = strncasecmp(s, "yes", 3);
	if(!ret) {
		*v->ivalue |= f;
		return ret;
	}
	return strncasecmp(s, "no", 2);
}

int token(char *s, union value_t *v, int f)
{
	char *p;
	p = strchr(s, '"');
	if(p) for(p = s; *p != '"'  &&  *p != '\n' ; p++) ;
	else for(p = s; !valid_sep(*p) &&  *p != '\n' ; p++) ;
	if(p == s) return 1;
	v->svalue = realloc((char *)v->svalue, (p - s) * sizeof (char) + 1);
	if(!v->svalue) errx(1, "cannot allocate memory. Exiting.");
	bzero(v->svalue, p - s + 1);
	strncpy(v->svalue, s, p - s);
	return 0;
}

int int_single(char *s, union value_t *v, int f)
{
	char *p = s;
	int i = 0;
	while(isdigit(*p))
		i = 10 * i + *(p++) - '0';
	*v->ivalue = i;
	if(p == s) return 1;
	return 0;
}
		
int int_list(char *s, union value_t *v, int f)
{
	char *p = s;
	int *c;
	int i, count;
	i = count = 0;
NEXT_VALUE:
	while(isdigit(*p))
		i = 10 * i + *(p++) - '0';
	count++;
	*v->iivalue = realloc(*v->iivalue, (count + 1) * sizeof(int));
	if(!*v->iivalue) errx(1, " cannot allocate memory. Exiting");
	c = *v->iivalue;
	*(c+count-1) = i;
	for(; *p == ' ' || *p == '\t'; p++);
	if(isdigit(*p)) { 
		i = 0;
		goto NEXT_VALUE;
	}	
	*(c+count) = 0;			
	if(*p == '\n') return 0;
	else return 1;
}

enum addr_type  { SRC_ADDR, DST_ADDR };

struct config_host *alloc_host(struct list_head *l)
{
	struct config_host *p;
	p = calloc(1, sizeof *p);
	if(!p) errx(1, "cannot allocate memory. Aborting");
	INIT_LIST_HEAD(&p->src.ports);
	INIT_LIST_HEAD(&p->dst.ports);
	addto_list(p, *l);
	return p;
}

static inline void skip_white(char **s)
{
	for(;**s == ' ' || **s == '\t'; (*s)++);
} 

static inline char *copy_addr(char *s, char *d, int len)
{
	int i;
	for(i = 0; isdigit(*s) || *s == '.' || *s == '/'; i++) {
		if(i == len - 1) break;
		*d++ = *s++;
	}
	*d = 0;
	return s;
}

static inline void get_val(int *i, char **s)
{
	*i = 0;
	while(isdigit(**s))
		*i = 10 * *i + *((*s)++) - '0';
}	

char *add_ports(char *s, struct host_t *t)
{
	int i = 0;
	struct port_range *pr;
NEXT_VALUE:
	get_val(&i, &s);
	pr = calloc(1, sizeof *pr);
	if(!pr) errx(1, "cannot allocate memory. Aborting");
	pr->start_port = i;
	pr->end_port = i;
	addto_list(pr, t->ports);
	skip_white(&s);	
	if(*s == '-' && *(s+1) != '>') {
		s++;
		get_val(&i, &s);
		pr->end_port = i;
	}
#ifdef DEBUG
	printf(" (%d, %d) ports added\n", pr->start_port, pr->end_port);
#endif
	if(*s == ',') { 
		s++;
		i = 0;
		goto NEXT_VALUE;
	}
	return s;
}

char *strnchr(char *s, int i, char c)
{
	int p;
	for(p = 0; *s && p < i; s++, p++)
		if(*s == c) return s;
	return 0;
} 	

/*
 * Parse IP/mask and fill addresses in the host_t structure.
 * Helper function for host_list()
 */
static int add_host(char *s, struct host_t *t)
{
	char *d;
	struct in_addr ip, mask;
	unsigned int n = 32;
	d = strchr(s, '/');
	if(d) {
		*d++ = 0;
		if (!sscanf(d,"%d", &n)) return 0;
	}
	if((d = strchr(s, ':'))) *d = 0;
	if(n) mask.s_addr = htonl(~((1ul << (32 -n)) - 1));
	else mask.s_addr = 0;
	
	if(!inet_aton(s, &ip)) return 0;
	ip.s_addr &= mask.s_addr;
	t->ip = ip;
	t->mask = mask;
#ifdef DEBUG
	printf(__FUNCTION__ ": %s %s found.\n", s, inet_ntoa(ip));
#endif
	return 1;
}
	
/*
 * This function adds config_host to the list in config_group (one
 * config_group is for TCP and one for UDP). Second argument is a pointer
 * to list head (host_scan_ign or host_log_ign) in struct config_group.
 */
int host_list(char *p, union value_t *v, int f)
{
	enum addr_type type = SRC_ADDR;
	char addr_string[32];
	char *x;
	struct config_host *c = 0;
	if (!*p) return 0;
NEXT_HOST:
	skip_white(&p);
	if(!isdigit(*p)) return 1;
	x = p;
	x = copy_addr(x, addr_string, 31);
	/* if src address then we must allocate another config_host structure */
	if(type == SRC_ADDR)
		c = alloc_host(v->xvalue);

	/* fill up ip and mask values in host_t structure */
	if(!add_host(addr_string, type==SRC_ADDR?&c->src:&c->dst))
		return 1;
	/* if it is dest_addr then mark it */
	if(type == DST_ADDR) c->dst_mark = 1;
		
	/* see if port description exists */
	skip_white(&x);
	if(*x == ':') 
		x = add_ports(x + 1, type==SRC_ADDR?&c->src:&c->dst);		
	skip_white(&x);
	if(isdigit(*x)) {
		p = x;
		c = 0;
		type = SRC_ADDR;
		goto NEXT_HOST;
	}
	/* see if dest_addr/mask:dest_ports specifiation exists */
	if(*x == '-' && *(x+1) == '>') {
		type = DST_ADDR;
		x += 2;
		p = x;
		goto NEXT_HOST;
	}
	if(*x == '\n') return 0;
	else return 1;
}

struct config_item config[] = {
	{ "LogConnections", boolean, {&tcp_opt.flags}, BOOLEAN, 0, LOG_CONN }, 
	{ "LogScans" , boolean, {&tcp_opt.flags}, BOOLEAN, 0, LOG_SCAN  },
	{ "SyslogFacility", log_facility , {&syslog_facility}, INT_SINGLE, 0, LOG_FACILITY  },
	{ "FloodDetection", boolean , {&flood_det}, BOOLEAN, 0, 1 },
	{ "LogDetails", boolean , {&log_details}, BOOLEAN, 0, 1 },
	{ "SendEmail", boolean, {&tcp_opt.flags}, BOOLEAN, 0, SEND_MAIL }, 
	{ "UdpLogConnections", boolean, {&udp_opt.flags}, BOOLEAN, 0, LOG_CONN }, 
	{ "UdpLogScans" , boolean, {&udp_opt.flags}, BOOLEAN, 0, LOG_SCAN  },
	{ "UdpSendEmail", boolean, {&udp_opt.flags}, BOOLEAN, 0, SEND_MAIL }, 
	{ "LogOSFP", boolean, {&osfp_options}, BOOLEAN, 0, LOG_SCAN }, 
	{ "OSFPSendMail", boolean, {&osfp_options}, BOOLEAN, 0, SEND_MAIL }, 
	{ "DNSResolve", boolean, {&dns_resolve}, BOOLEAN, 0, 1 },
	{ "PortResolve", boolean, {&port_resolve}, BOOLEAN, 0, 1 },
	{ "MailFrom", token, {0}, STRING, MAIL_FROM, 0 },
	{ "RcptTo", token, {0}, STRING, RCPT_TO, 0 },
	{ "MailSubject", token, {0}, STRING, MAIL_SUBJECT, 0 },
	{ "SMTPRelay", token, {0}, STRING, SMTP_RELAY, 0 },
	{ "MailPort", int_single, {&mail_port}, INT_SINGLE, 0, 0 },
	{ "HelloMsg", token, {0}, STRING, HELLO_MSG, 0 },
	{ "RunAsUser", token, {0}, STRING, RUN_AS_USER, 0 },
//	{ "RunAsGroup", token, {0}, STRING, RUN_AS_GROUP, 0 },
	{ "CountThreshold" , int_single, {&count_threshold}, INT_SINGLE, 0, 0 },
	{ "PortLogIgnore", int_list, {(int *)&tcp_opt.port_log_ignore}, INT_LIST, 0, 0 },
	{ "PortScanIgnore", int_list, {(int *)&tcp_opt.port_scan_ignore}, INT_LIST, 0, 0 },
	{ "UdpPortLogIgnore", int_list, {(int *)&udp_opt.port_log_ignore}, INT_LIST, 0, 0 },
	{ "UdpPortScanIgnore", int_list, {(int *)&udp_opt.port_scan_ignore}, INT_LIST, 0, 0 },
	{ "HostLogIgnore", host_list, {(int *)&tcp_opt.host_log_ign}, HOST_LIST, 0, 0 },
	{ "HostScanIgnore", host_list, {(int *)&tcp_opt.host_scan_ign}, HOST_LIST, 0, 0 } ,
	{ "UdpHostLogIgnore", host_list, {(int *)&udp_opt.host_log_ign}, HOST_LIST, 0, 0 },
	{ "UdpHostScanIgnore", host_list, {(int *)&udp_opt.host_scan_ign}, HOST_LIST, 0, 0 } 
};

static void clear_ports(int **i)
{
	if(*i) {
		free(*i);
		*i = 0;
	}
		
}

static void clear_port_list(struct list_head *ports)
{
	struct port_range *p, *next;
	p = ports->next;
	while(p != (void *) ports) {
		next = p->next;
		free(p);
		p = next;
	}
}

void clear_conf(struct config_group *c)
{
	struct config_host *h, *ptr;
	clear_ports(&c->port_log_ignore);
	clear_ports(&c->port_scan_ignore);
	h = c->host_log_ign.next;
	while(h != (void *) &c->host_log_ign) {
		ptr = h->next;
		clear_port_list(&h->src.ports);
		clear_port_list(&h->dst.ports);
		free(h);
		h = ptr;
	}
	INIT_LIST_HEAD(&c->host_log_ign);
	h = c->host_scan_ign.next;
	while(h != (void *) &c->host_scan_ign) {
		ptr = h->next;
		clear_port_list(&h->src.ports);
		clear_port_list(&h->dst.ports);
		free(h);
		h = ptr;
	}
	INIT_LIST_HEAD(&c->host_scan_ign);
}

/*
 * Parse config file. Call appriopriate function for each
 * recognized config option to set value.
 */
void read_conf(void)
{
	FILE *f;
	char buf[128], *p = buf;
	int (*prev)(char *, union value_t *, int);
	int n, i, len, found = 0;
	i = n = found = 0;
	if (!(f = fopen(CONFIG_FILE, "r"))) 
		errx(1, "Cannot open config file: " CONFIG_FILE);
	while (fgets(buf, sizeof buf, f)){
		n++;
		if (buf[0] == '#' || buf[0] == '\n') continue;
		for(i = 0; i < sizeof config/sizeof (struct config_item); i++) {
			len = strlen(config[i].t);
			if(strncasecmp(buf, config[i].t, len)) {
				found = 0; 
				continue;
			}	
			found = 1;
			for(p = buf + len; valid_sep(*p); p++) ;
			if(config[i].f(p, &config[i].value, config[i].mask))
				errx(1, "Syntax error in " CONFIG_FILE " (line %d)\n", n);
			prev = config[i].f;
			break;
		}
		if(!found) errx(1, "Unrecognized config option in %d line. Aborting", n);	
	}
	fclose(f);
}	


/*                                                                                     
 * If some config options were not found in config file                                
 * then load defaults (default values are in config.h and config[])                                 
 */                                                                                    
void load_defaults(void)                      
{                

        int i;
	struct config_item *tmp;
	for(i = 0; i < sizeof config/sizeof (struct config_item); i++) {
		tmp = &config[i];
		if(tmp->val_type == BOOLEAN) {
			*tmp->value.ivalue = 0;
			continue;
		}
		if(!tmp->value.ivalue && tmp->defaults) 
			tmp->f(tmp->defaults, &tmp->value, tmp->mask);
	}
	return;

}

struct config_item *get_config_item(char *s)
{
	int i;
	struct config_item *tmp;
	for(i = 0; i < sizeof config/sizeof (struct config_item); i++) {
		tmp = &config[i];
		if(!strncasecmp(s, tmp->t, strlen(s)))
			return tmp;
	}
	return 0;
}	

void print_host(struct host_t *h)
{
	struct port_range *pr;
	struct in_addr addr;
	int i = 0;
	addr.s_addr = h->ip.s_addr & h->mask.s_addr;
	/* source address should be always present */
	if(!addr.s_addr) printf("any ");
	else printf("%s ", inet_ntoa(addr));
	for_each(pr, h->ports) {
		if(!i++) printf("(");
		if(i > 1) printf(" ");
		printf("%d", pr->start_port);
		if(pr->start_port != pr->end_port)
			printf("-%d", pr->end_port);
	}
	if(i) printf(") ");
}

void show_conf(void)
{
	int i;
	int *p;
	struct config_host *h;
	struct config_item *tmp;
	printf("\nCurrent configuration:\n\n");
	for(i = 0; i < sizeof config/sizeof (struct config_item); i++) {
		tmp = &config[i];
		printf("%-18s", tmp->t);
		switch(tmp->val_type) {
		case BOOLEAN:
			printf(*tmp->value.ivalue&tmp->mask?"true":"false");
			printf("\n");
			break;
		case STRING:
			printf("%s\n", tmp->value.svalue);
			break;
		case INT_LIST:
			for(p = *tmp->value.iivalue; p && *p; p++)
				printf("%d ", *p);
			printf("\n");
			break;
		case INT_SINGLE:
			printf("%d\n", *tmp->value.ivalue);
			break;
		case HOST_LIST:
			for_each(h, *tmp->value.xvalue) {
				printf("\n\t");
				print_host(&h->src);
				if(!h->dst_mark) continue;
				printf("-> ");
				print_host(&h->dst);
			}		
			printf("\n");		
			break;
		}
	}
	printf("\n");
}	

