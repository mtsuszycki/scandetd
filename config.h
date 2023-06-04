/*
 * Name and path to the configuration file
 */
#define CONFIG_FILE "/etc/scandetd.conf"

/*
 * Name of the pid file
 */
#define PID_FILE "/var/run/scandetd.pid" 

/*
 * You can add 
 * "local2.*	-/var/log/scandetd"
 * line to your syslog.conf or read openlog(3) and change
 * this define to suit your needs.
 */
#define LOG_FACILITY	LOG_LOCAL3

/* 
 * how many hosts should I remember. If your server is heavily loaded it's
 * good idea to increase this number a little bit
 */
#define HOW_MANY 20

/*
 * how many connections should I recognize as scanning?
 */
#define COUNT_THRESHOLD		 20

/* 
 * These are defaults. You can change them in configuration file.
 */
#define MAIL_FROM		"SCANDETD@localhost"
#define RCPT_TO			"root@localhost"
#define MAIL_SUBJECT		"Scan"
#define SMTP_RELAY		"127.0.0.1"
#define MAIL_PORT		25
#define RUN_AS_USER		"nobody"
#define RUN_AS_GROUP		"nobody"
#define HELLO_MSG		"localhost"

/* 
 * If a connection from the same host was right after the previous
 * one (default threshold is 1 second) then increase counter. 
 */
#define SEC	 1

