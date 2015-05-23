#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/timer.h>
#include "domain_hash.h"

#define IP_DOMAIN_MAP_NUM 512
#define NAME_MAX 128

/// ip-domain 结点
struct ip_domain_map;
struct ip_domain{
	struct hlist_node node;
	__be32 ip;
	const char name[NAME_MAX];
	__u16 ttl;   ///< dns rr ttl
	struct ip_domain_map *map;
	struct timer_list timer;
};

/// ip—domain 结构
struct ip_domain_map{
	struct hlist_head hash[IP_DOMAIN_MAP_NUM];
	spinlock_t lock;
};

static struct ip_domain_map map;

/// @brief ip_domain 超时函数
static void time_out(unsigned long data){
	struct ip_domain *d=(struct ip_domain*)data;
	spin_lock(&d->map->lock);
	if(d->ttl==0){
		hlist_del(&d->node);
		spin_unlock(&d->map->lock);
		kfree(d);
		return;
	}
	d->ttl--;
	spin_unlock(&d->map->lock);
	mod_timer(&d->timer,jiffies+1);
	return;
}

/// @brief 分配ip_domain
/// @retval 失败返回NULL
static struct ip_domain * alloc_ip_domain(void){
	struct ip_domain *d=kmalloc(sizeof(struct ip_domain),GFP_ATOMIC);
	if(NULL==d)
		return NULL;
	/// 初始化
	d->map=NULL;
	init_timer(&d->timer);
	d->timer.function=time_out;
	d->timer.data=(unsigned long)d;
	return d;
}

/// @brief 设置超时值
static void set_ip_domain_timeout(struct ip_domain *d,int sec){
	d->timer.expires=jiffies+HZ*sec;
	add_timer(&d->timer);
}

/// @brief 修改超时值
static void mod_ip_domain_timeout(struct ip_domain *d,int sec){
	del_timer(&d->timer);
	d->timer.expires=jiffies+HZ*sec;
	add_timer(&d->timer);
}

/// @brief 初始化map
static void init_ip_domain_map(struct ip_domain_map *map){
	int i=0;
	spin_lock_init(&map->lock);
	for(i=0;i<IP_DOMAIN_MAP_NUM;i++)
		INIT_HLIST_HEAD(map->hash+i);
}

/// @biref 释放ip_domain_map
static void free_ip_domain_map(struct ip_domain_map *map){
	int i=0;
	struct ip_domain *d=NULL;
	spin_lock(&map->lock);
	struct hlist_node *n;
	for(i=0;i<IP_DOMAIN_MAP_NUM;i++)
		hlist_for_each_entry_safe(d,n,map->hash+i,node){
			/// 删除d
			hlist_del(&d->node);
			del_timer(&d->timer);
			kfree(d);
		}
	spin_unlock(&map->lock);
}

/// @brief 依据ip查找domain
/// @retval 成功返回struct ip_domain指针,否则返回NULL
static struct ip_domain* __find_ip_domain_map(struct ip_domain_map *map,__be32 ip,unsigned int key){
	struct hlist_head *head=NULL;
	struct ip_domain *d=NULL;
	head=map->hash+key;
	hlist_for_each_entry(d,head,node){
		if(d->ip==ip)
			return d;
	}
	return false;
}

/// @brief 添加ip,domain到map
static void add_ip_domain_map(struct ip_domain_map *map,__be32 ip,const char *name,__u16 ttl){
	struct ip_domain *d=NULL;
	unsigned int key=0;

	key=hash_key(ip)%IP_DOMAIN_MAP_NUM;
	if(strlen(name)>IP_DOMAIN_MAP_NUM-1)
		return;
	spin_lock(&map->lock);
	d=__find_ip_domain_map(map,ip,key);
	if(d==NULL){
		d=alloc_ip_domain();
		if(NULL!=d){
			d->ip=ip;
			strcpy(d->name,name);
			d->ttl=ttl;
			d->map=map;
			hlist_add(&d->node,map->hash+key);
			set_ip_domain_timeoute(d,1);
		}
		spin_unlock(&map->lock);
		return;
	}
	strcpy(d->name,name);
	d->ttl=ttl;
	spin_unlock(&map->lock);
};

/// @brief hash函数
unsigned int hash_key(__be32 ip){
	unsigned int key=ip&0x0000ffff;
	return key;
}

/// @brief 依据ip查找域名 
/// @retval 成功返回域名,否则返回NULL
char * domain_hash_find_name(__be32 ip){
	unsigned int key=hash_key(ip);
	struct hlist_head *head;
	struct ip_domain *d=NULL;
	char *ret=NULL;
	key%=IP_DOMAIN_MAP_NUM;
	spin_lock(&map.lock);
	d=__find_ip_domain_map(&map,ip,key);
	if(d==NULL){
		spin_unlock(&map.lock);
		return NULL;
	}
	ret=kmalloc(strlen(d->name)+1,GFP_ATOMIC);
	if(NULL==ret){
		return NULL;
		spin_unlock(&map.lock);
	}
	strcpy(ret,d->name);
	return ret;
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
	init_ip_domain_map(&map);
	/// 注册钩子
	if(nf_register_hook(&ops)<0){
		pr_err("register hook_ops error\n");
		return -1;
	}
	pr_info("load domain_hahs ok!\n");
	return 0;
}

static void __exit domain_hash_exit(void){
	nf_unregister_hook(&ops);
	free_ip_domain_map(&map);
	pr_info("unload domain_hash ok!\n");
}

module_init(domain_hash_init);
module_exit(domain_hash_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("a hash struct for ip->domain");
MODULE_AUTHOR("hzy.oop@gmail.com");
