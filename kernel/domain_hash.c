#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/list.h>
#include <linux/slab.h>
#include "domain_hash.h"


/// @brief 依据ip查找域名 
/// @retval 成功返回域名,否则返回NULL
char * domain_hash_find_name(__be32 ip){
	return NULL;
}
EXPORT_SYMBOL(domain_hash_find_name);

/// 钩子函数
static unsigned int hook_fun(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *)){
	return NF_ACCEPT;
}


/// 钩子结构
static struct nf_hook_ops ops={
	.owner=THIS_MODULE,
	.hooknum=NF_INET_PRE_ROUTING,
	.pf=AF_INET,
	.priority=NF_IP_PRI_LAST,
	.hook=hook_fun,
};

static int __init domain_hash_init(void){
	if(nf_register_hook(&ops)<0){
		pr_err("register hook_ops error\n");
		return -1;
	}
	pr_info("load domain_hahs ok!\n");
	return 0;
}

static void __exit domain_hash_exit(void){
	nf_unregister_hook(&ops);
	pr_info("unload domain_hash ok!\n");
}

module_init(domain_hash_init);
module_exit(domain_hash_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("a hash struct for ip->domain");
MODULE_AUTHOR("hzy.oop@gmail.com");
