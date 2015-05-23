#ifndef _XT_DOMAIN_H
#define _XT_DOMAIN_H
#include <linux/types.h>

#define XT_DOMAIN_BUFSIZE 512
enum {
	XT_IPADDR_SRC =1 <<0,
	XT_IPADDR_DST =1 <<1,
	XT_IPADDR_SRC_INV =1 <<2,
	XT_IPADDR_DST_INV= 1<< 3,
};


struct xt_domain_mtinfo {
	__u8 flags;           ///< match flags
	char names[XT_DOMAIN_BUFSIZE];   ///< names buffer
};

#endif
