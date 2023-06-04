#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <syslog.h>
#include <errno.h>
#include <sys/types.h>  
#include <sys/socket.h>
#include <sys/wait.h>   
#include <sys/stat.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netdb.h>
#include <time.h>
#include <signal.h>
#include <string.h>
#include <ctype.h> 
#include <err.h>

                                                                                         
#if (linux)  
#define __FAVOR_BSD 
#endif
                                                                                         
#include <netinet/in_systm.h> 
#include <netinet/ip.h>    
#include <netinet/tcp.h>   
#include <arpa/inet.h> 

#include "list.h"
                      
#define ALARM_TIMEOUT	15
#define SCAN_TIMEOUT	15

#define PROT_NR		2	/* number of supported protocols */

#define LOG_CONN        0x1                                                         
#define LOG_SCAN        0x2                                                         
#define SEND_MAIL       0x4 

extern int dns_resolve;          
extern int port_resolve;           
extern int mail_port;
extern int count_threshold;
                               

enum vtype { BOOLEAN, STRING, INT_LIST, HOST_LIST, INT_SINGLE };
enum prot_type { TCP_TYPE, UDP_TYPE } ;


/* 
 * This structure is used in host_t to make
 * linked list with "ports" as a list head.
 */
struct port_range
{
	struct port_range *next;
	struct port_range *prev;
	u_int16_t start_port;
	u_int16_t end_port;
};

struct host_t
{
	struct in_addr ip, mask;
	struct list_head ports;
};

/*
 * config_host creates linked list in config_group
 * with host_log_ign and host_scan_ign as list heads
 */
struct config_host
{
	struct config_host *next;
	struct config_host *prev;
	struct host_t src;
	struct host_t dst;
	int dst_mark;
};

union value_t {
	int *ivalue;
	int **iivalue;
	char *svalue;
	struct config_host **hvalue;	
	struct list_head *xvalue;
};

/*
 * This one contains all necessary information to parse config file
 * see config.c
 */
struct config_item
{
	char *t;				  	/* config token 		*/
	int (*f)(char *s, union value_t *v, int f);	/* function that sets the value	*/
	union value_t value;				/* variable's value 	*/
	enum vtype val_type;				/* type of the value	*/			
	char *defaults;
	int mask;					/* mask used for setting flags */
};

struct tcppkt {
	struct ip ip;
	struct tcphdr tcp;
} ;


struct udppkt {
	struct ip ip;
	struct udphdr udp;
} ;


struct any_pkt {
	struct ip ip;
	u_int16_t source;	/* source port 		*/
	u_int16_t dest;		/* destination port	*/
};

#define SCAN_LOGGED	0x1
#define MAIL_SENT	0x2
#define DST_CHANGED	0x4

struct host{
	enum prot_type prot;
	unsigned int from;
	unsigned int dst;
	time_t t;
	time_t start;
	unsigned short low_port;
	unsigned short hi_port;
	unsigned short prev_port;
	unsigned int count, fin_count, syn_count;
	time_t last_scan;
	int flood;	/* increased if dest_port was the same in previous packet */
	int flags;	/* see defines above */
	int osfp_flags;	/* used only for OS fingerprinting probes detection */
};

/*
 * Group of config options. This structure is filled by
 * read_conf() and used in serveral internal routines.
 * One group for TCP and one for UDP protocol.
 */
struct config_group {
	unsigned int flags;
	int *port_log_ignore;
	int *port_scan_ignore;
	struct list_head host_scan_ign;
	struct list_head host_log_ign;
};


extern struct config_group tcp_opt, udp_opt;

struct config_item *get_config_item(char *);
int boolean(char *, union value_t *, int);
int token(char *, union value_t *, int);
int int_list(char *, union value_t *, int);
int host_list(char *, union value_t *, int);
void clear_conf(struct config_group *);
void read_conf(void);
void show_conf(void);
void load_defaults(void);

void setup_variables(void);
