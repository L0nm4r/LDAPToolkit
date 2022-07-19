# 扫描
```
./LDAPToolkit --target-ip=192.168.6.100 --user=administrator --token=3f7528021486bb6e9e10287b9341aa23 --token-type=hash --domain=red.local scan
./LDAPToolkit --target-ip=192.168.6.100 --user=red\administrator --token='Abc@123!' --token-type=password --domain=red.local scan
```
# 查询
```
./LDAPToolkit --target-ip=192.168.6.100 --user=red\administrator --token='Abc@123!' --token-type=password --domain=red.local search DC=red,DC=local --filter="ObjectClass=user" --attributes=dn
./LDAPToolkit --target-ip=192.168.6.100 --user=red\administrator --token='Abc@123!' --token-type=password --domain=red.local search "CN=Domain Admins,CN=users,DC=red,DC=local" --filter="ObjectClass=group" --attributes=member
```
空filter:
```
./LDAPToolkit --target-ip=192.168.6.100 --user=red\administrator --token='Abc@123!' --token-type=password --domain=red.local search DC=red,DC=local name=*   dn
```
# 增
```
./LDAPToolkit --target-ip=192.168.6.100 --user=red\administrator --token='Abc@123!' --token-type=password --domain=red.local attrAdd CN=testuser1,CN=users,DC=red,DC=local ObjectClass=user servicePrincipalName test1/test2 test2/test3
# 增加用户到组
./LDAPToolkit --target-ip=192.168.6.100 --user=red\administrator --token='Abc@123!' --token-type=password --domain=red.local attrAdd "CN=Domain Admins,CN=users,DC=red,DC=local" ObjectClass=group member CN=u101,CN=users,DC=red,DC=local
```
# 改
```
./LDAPToolkit --target-ip=192.168.6.100 --user=red\administrator --token='Abc@123!' --token-type=password --domain=red.local attrReplace CN=testuser1,CN=users,DC=red,DC=local ObjectClass=user servicePrincipalName test22/test2 test22/test3
```
# 删
```
./LDAPToolkit --target-ip=192.168.6.100 --user=red\administrator --token='Abc@123!' --token-type=password --domain=red.local attrClear CN=testuser1,CN=users,DC=red,DC=local ObjectClass=user servicePrincipalName
```
# entryDel : 删除账户等

```
./LDAPToolkit --target-ip=192.168.6.100 --user=red\administrator --token='Abc@123!' --token-type=password --domain=red.local entryDel CN=m1011,CN=computers,DC=red,DC=local
```
# add-user: 添加机器用户/域用户
```
./LDAPToolkit --target-ip=192.168.6.100 --user=red\administrator --token='Abc@123!' --token-type=password --domain=red.local add-user user u102
./LDAPToolkit --target-ip=192.168.6.100 --user=red\administrator --token='Abc@123!' --token-type=password --domain=red.local add-user machine m1011
```