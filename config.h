#ifndef CONFIG_H
#define CONFIG_H

#define LISTENADDRESS   "0.0.0.0"
#define DEFAULTPORT     22
#define RSA_KEYFILE     "/etc/sshpot/rsa.key"
#define LOGFILE         "/var/log/sshpot/auth.log"
#define DEBUG           0

/* the default number of maximum connections */
#define DEF_CONNECTIONS 15

/* the upper limit of connections that can be requested */
#define MAXCONN         200

#endif
