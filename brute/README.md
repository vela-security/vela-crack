## 线上爆破模块
### v1.0
##### 实现并已成功测试的组件包括：
`elastic`
`ftp`
`mongodb`
`mysql`
`rdp`
`redis`
`smtp`
`ssh`
`公司使用vpn`
##### 已经完成但是还没有经过测试的组件包括：
`mssql`
`oracle`
`postgres`
`smb`
`snmp`

## 使用手册

### `example`
```lua
local function handle(ev)
  vela.Debug("crack %v" , ev)
end
local b = crack.brute("crack").use("root").pass("123456@")
b = b.cidr("172.11.11.111/28").thread(10).pipe(handle)
b.ssh{
  port = 22,
  timeout = 1,
}
-- b.mysql{
--   port = 3306
-- }
-- b.ftp{
--   port = 21
-- }
-- b.elastic{
--   scheme = "http",
--   port = 9200
-- }
-- b.mongodb{
--   port = 27017,
-- }
-- b.rdp{
--   port = 3389,
-- }
-- b.redis{
--   port = 6379,
--   timeout = 1,
-- }
-- b.smb{
--   port = 445,
--   timeout = 1,
-- }
-- b.smtp{
--   port = 25,
--   timeout = 1,
-- }
-- b.snmp{
--   port = 161,
--   timeout = 1,
-- }
-- b.web{
--   method = "POST",
--   url = "https://security.eastmoney.com/srclogin/Home/SubmitLogin",
--   query = "userName={user}&password={pass}&hidUrl=",
--   contenttype = "application/x-www-form-urlencoded; charset=UTF-8",
--   proxy = "http://127.0.0.1:8080",
--   checkstatus = 200,
--   checkstr = "administrator",
--   timeout = 1,
-- }

b.start()
```
其中用户名，密码，ip池字段 user，pass，cidr;  
首字母小写代表直接取相应值  
首字母大写时：User，Pass，Cidr代表取相应值作为文件路径

其中web爆破的query字段中使用{user}占位用户名，{pass}占位密码。
 
### 使用介绍
根据调用的组件和传入的端口进行线上爆破
爆破成功会触发相应的事件日志，后续增加告警等措施
