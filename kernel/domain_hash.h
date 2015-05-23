#ifndef _HASH_DOMAIN_H
#define _HASH_DOMAIN_H

/// @brief 依据ip查找域名 
/// @retval 成功返回域名,否则返回NULL
char * domain_hash_find_name(__be32 ip);
#endif
