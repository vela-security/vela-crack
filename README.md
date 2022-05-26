# 密码爆破模块
分为线上爆破模块：`crackonline`和离线爆破模块：`john`

## 线上爆破模块
根据不同协议进行爆破
## 离线爆破模块
目前仅支持`shadow`文件爆破和`MD5`，`sha256`,`sha512`格式的爆破

## 加载方式
```
	john.WithEnv(env, kv)
	brute.WithEnv(env, kv)
	env.Global("crack", kv)
```
