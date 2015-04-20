#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "php.h"
/* Includes */
#include <sys/param.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/ioctl.h>
#include <net/bpf.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

#include <netdb.h>
#include <errno.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <paths.h>
#include <unistd.h>
#include <ifaddrs.h>

#include <stdio.h>
#include <stdlib.h>
#define PHP_ARP_VERSION "1.0"
#define PHP_ARP_EXTNAME "arp"
 
extern zend_module_entry arp_module_entry;
#define phpext_arp_ptr &arp_module_entry
void search(in_addr_t addr, void (*action)(struct sockaddr_dl *sdl, struct sockaddr_inarp *sin, struct rt_msghdr *rtm));
void print_entry(struct sockaddr_dl *sdl,	struct sockaddr_inarp *sin, struct rt_msghdr *rtm);
void ether_print(const char *);
int getinetaddr(const char *, struct in_addr *);
struct sockaddr_in	so_mask = { 8, 0, 0, { 0xffffffff } };
struct sockaddr_inarp	blank_sin = { sizeof(blank_sin), AF_INET }, sin_m;
struct sockaddr_dl	blank_sdl = { sizeof(blank_sdl), AF_LINK }, sdl_m;
time_t			expire_time;
int			flags, export_only, doing_proxy, found_entry;
struct	{
	struct rt_msghdr	m_rtm;
	char			m_space[512];
}	m_rtmsg;
char ll_macaddr[18] ;

// declaration of a custom arp_get_mac()
PHP_FUNCTION(arp_get_mac);
 
static zend_function_entry arp_functions[] = {
    PHP_FE(arp_get_mac, NULL)
    {NULL, NULL, NULL}
};
 
// the following code creates an entry for the module and registers it with Zend.
zend_module_entry arp_module_entry = {
#if ZEND_MODULE_API_NO >= 20010901
    STANDARD_MODULE_HEADER,
#endif
    PHP_ARP_EXTNAME,
    arp_functions,
    NULL, // name of the MINIT function or NULL if not applicable
    NULL, // name of the MSHUTDOWN function or NULL if not applicable
    NULL, // name of the RINIT function or NULL if not applicable
    NULL, // name of the RSHUTDOWN function or NULL if not applicable
    NULL, // name of the MINFO function or NULL if not applicable
#if ZEND_MODULE_API_NO >= 20010901
    PHP_ARP_VERSION,
#endif
    STANDARD_MODULE_PROPERTIES
};
 
ZEND_GET_MODULE(arp)
 
// implementation of a custom arp_get_mac()

/* Type some extra information about our module
 * in phpinfo().
 */
PHP_MINFO_FUNCTION(arp_mod_info)
{
	php_info_print_table_start();
	php_info_print_table_header(1, "OpenBSD ARP Extension");
	php_info_print_table_row(2, "Version", "0.1");
	php_info_print_table_row(2, "Created by", "Echothrust Solutions");
	php_info_print_table_row(2, "Licence", "BSD");
	php_info_print_talbe_end();
}




PHP_FUNCTION(arp_get_mac)
{
	zval *zptr =0, *copy=0;
	int mib[7],found_entry;
	size_t needed,cstrlen;
	char *lim,*buf=NULL,*next;
	char *ipaddr;
	struct sockaddr_dl *sdl;
	in_addr_t addr;
	struct sockaddr_inarp   blank_sin = { sizeof(blank_sin), AF_INET }, sin_m;
    struct sockaddr_inarp *sin;
    struct rt_msghdr *rtm;
    u_char *cp;
    
	/* check number of arguments */
	if (ZEND_NUM_ARGS() != 1)
		WRONG_PARAM_COUNT;

	/* parse arguments */
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &zptr) == FAILURE)
		return;
		
	if (Z_TYPE_P(zptr) != IS_STRING) {
	    ALLOC_INIT_ZVAL(copy);
	    *copy = *zptr;
	    INIT_PZVAL(copy); /* reset refcount and clear is_ref */
	    zval_copy_ctor(copy);
	    convert_to_string(copy);
	} else {
	    copy = zptr;
	}

	cstrlen = Z_STRLEN_P(copy);
	ipaddr = estrndup(Z_STRVAL_P(copy), cstrlen);
	sin = &sin_m;
	sin_m = blank_sin;		/* struct copy */
	if (getinetaddr(ipaddr, &sin->sin_addr) == -1)
		RETURN_FALSE;
	memset(ll_macaddr,0x0,sizeof(ll_macaddr));
	search(sin->sin_addr.s_addr, print_entry);
	RETURN_STRINGL(ll_macaddr,17,0);
}


/*
 * Search the entire arp table, and do some action on matching entries.
 */
void
search(in_addr_t addr, void (*action)(struct sockaddr_dl *sdl,
    struct sockaddr_inarp *sin, struct rt_msghdr *rtm))
{
	int mib[7];
	size_t needed;
	char *lim, *buf = NULL, *next;
	struct rt_msghdr *rtm;
	struct sockaddr_inarp *sin;
	struct sockaddr_dl *sdl;

	mib[0] = CTL_NET;
	mib[1] = PF_ROUTE;
	mib[2] = 0;
	mib[3] = AF_INET;
	mib[4] = NET_RT_FLAGS;
	mib[5] = RTF_LLINFO;
	mib[6] = getrtable();
	while (1) {
		if (sysctl(mib, 7, NULL, &needed, NULL, 0) == -1)
			err(1, "route-sysctl-estimate");
		if (needed == 0)
			return;
		if ((buf = realloc(buf, needed)) == NULL)
			err(1, "malloc");
		if (sysctl(mib, 7, buf, &needed, NULL, 0) == -1) {
			if (errno == ENOMEM)
				continue;
			err(1, "actual retrieval of routing table");
		}
		lim = buf + needed;
		break;
	}
	for (next = buf; next < lim; next += rtm->rtm_msglen) {
		rtm = (struct rt_msghdr *)next;
		if (rtm->rtm_version != RTM_VERSION)
			continue;
		sin = (struct sockaddr_inarp *)(next + rtm->rtm_hdrlen);
		sdl = (struct sockaddr_dl *)(sin + 1);
		if (addr) {
			if (addr != sin->sin_addr.s_addr)
				continue;
			found_entry = 1;
		}
		(*action)(sdl, sin, rtm);
	}
	free(buf);
}

/*
 * Display an arp entry
 */
void
print_entry(struct sockaddr_dl *sdl, struct sockaddr_inarp *sin,
    struct rt_msghdr *rtm)
{
	char ifname[IFNAMSIZ], *host;
	struct hostent *hp;

	hp = 0;
	host = "?";
	if (sdl->sdl_alen)
		ether_print(LLADDR(sdl));
}
void
ether_print(const char *scp)
{
	const u_char *cp = (u_char *)scp;
    sprintf(ll_macaddr,"%02x:%02x:%02x:%02x:%02x:%02x", cp[0], cp[1], cp[2], cp[3], cp[4], cp[5]);
}

int
getinetaddr(const char *host, struct in_addr *inap)
{
	struct hostent *hp;

	if (inet_aton(host, inap) == 1)
		return (0);
	if ((hp = gethostbyname(host)) == NULL) {
		warnx("%s: %s", host, hstrerror(h_errno));
		return (-1);
	}
	memcpy(inap, hp->h_addr, sizeof(*inap));
	return (0);
}
