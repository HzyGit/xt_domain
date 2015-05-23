#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>

#include "domain_hash.h"

/// @brief 依据ip查找域名 
/// @retval 成功返回域名,否则返回NULL
char * domain_hash_find_name(__be32 ip){
	return NULL;
}
EXPORT_SYMBOL(domain_hash_find_name);

static int __init domain_hash_init(void){
	pr_info("load domain_hahs ok!\n");
	return 0;
}

static void __exit domain_hash_exit(void){
	pr_info("unload domain_hash ok!\n");
}

module_init(domain_hash_init);
module_exit(domain_hash_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("a hash struct for ip->domain");
MODULE_AUTHOR("hzy.oop@gmail.com");
