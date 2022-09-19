# nmScan_go
一款基于GO语言编写的支持调用fofa搜索结果、masscan json格式扫描结果、直接调用ip和ip:port格式4种方式进行nmap快速扫描，多种格式输出的主机端口信息的收集工具

## 介绍：
```
./nmScan_go -h

              ______
             / _____)
 ____  ____ ( (____   ____ _____ ____
|  _ \|    \ \____ \ / ___|____ |  _ \
| | | | | | |_____) | (___/ ___ | | | |
|_| |_|_|_|_(______/ \____)_____|_| |_|  Ver:1.1

https://github.com/rambleZzz/nmScan_go
nmScan: v1.1	Dev:go1.7


NAME:
   nmScan_go - 一款基于GO语言编写的支持调用fofa搜索结果、masscan json格式扫描结果、
               直接调用ip和ip:port格式4种方式进行nmap快速扫描，多种格式输出的主机端口信息的收集工具

USAGE:
   nmScan -f ip.txt -m ip                                (ip格式扫描模式，使用内置的常见端口扫描，并输出结果至sqlite)
   nmScan -f ip.txt -m ip -p 22,445,3306,6379,8001-8005  (ip格式扫描模式，并指定端口扫描，并输出结果至sqlite)
   nmScan -f ip.txt -m iport                             (ip:port格式扫描模式，并输出结果至sqlite)
   nmScan -f ip.txt -m fofa                              (从fofa搜索ip开放端口扫描模式,fofa模式支持ip、ip/24、ip/25等格式内容，并输出结果至sqlite)
   nmScan -f ip.json -m masjson                          (解析masscan json扫描结果后的扫描模式，并输出结果至sqlite)
   nmScan -f ip.txt -m fofa -oT                          (输出结果至sqlite和txt)

   -oS表示输出到sqlite，此参数默认为true,不加也会输出,如果-oS false表示不输出至sqlite
   -oT表示输出到txt，此参数默认为false,如果需要导出到文本需添加此参数
   f和m参数为必填项，其他参数为可选项，更多参数请参考GLOBAL OPTIONS

VERSION:
   v1.0

COMMANDS:
   help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --file value, -f value     从txt或json文件中读取内容 ip.txt/ip.json
   --help, -h                 show help (default: false)
   --model value, -m value    model参数决定目标解析及扫描方式(四选一) ip/iport/masjson/fofa
   --oSqlite, --oS            是否输出到sqlite (default: true)
   --oTxt, --oT               是否输出到txt  (default: false)
   --port value, -p value     指定扫描的端口 如22,80,3306,8081-8090
   --threads value, -t value  扫描线程数  (default: 100)
   --version, -v              print the version (default: false)

```  
首次执行会自动生成config.yaml配置文件，如果需要fofa搜索扫描模式请先填写fofa认证配置信息

```
#nmScan Yaml config
fofa:
  FOFA_EMAIL: xxxx@xxxx.com
  FOFA_KEY: xxxxxxxxxxxxxxxxx
  FOFA_SEARCH_SIZE: 2000  #fafa一次搜索返回的数量
scan:
  PortOpenCountLimit: 100 #可能防火墙过滤原因导致开放端口超过多少个,不对此IP结果进行导出
  NMAPsV: false #是否进行nmap -sV 端口服务版本探测
 ``` 

## 使用帮助:
#### 1、直接ip扫描模式：  
```
./nmScan_go -m ip -f ip.txt -p 3306,8834,8000,8080,8081 -oT
-p 参数不添加默认扫描top1000端口  
扫描目标格式如下：  
127.0.0.1  
36.x.x.x  
58.x.x.x
```
#### 2、ip:port扫描模式：
````
./nmScan_go -m iport -f ip.txt -oT
扫描目标格式如下：
127.0.0.1:8834,7890,3334,3306
36.x.x.x:8000,8080,8081
58.x.x.x:8081
````
#### 3、解析masscan json扫描结果后的扫描模式：
```
(请先使用masscan扫描 masscan -p 1-65535 -oJ test.json)
./nmScan_go -m masjson -f test.json -oT
扫描目标格式如下：

[
  {   "ip": "36.x.x.x",   "timestamp": "1660632253", "ports": [ {"port": 8080, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 124} ] }
,
  {   "ip": "36.x.x.x",   "timestamp": "1660632253", "ports": [ {"port": 8000, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 60} ] }
,
  {   "ip": "36.x.x.x",   "timestamp": "1660632253", "ports": [ {"port": 8088, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 124} ] }
,
  {   "ip": "58.x.x.x",   "timestamp": "1660632253", "ports": [ {"port": 8089, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 124} ] }
,
  {   "ip": "58.x.x.x",   "timestamp": "1660632255", "ports": [ {"port": 8081, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 124} ] }
,
  {   "ip": "127.0.0.1",   "timestamp": "1660632255", "ports": [ {"port": 22, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 124} ] }
,
  {   "ip": "127.0.0.1",   "timestamp": "1660632255", "ports": [ {"port": 3306, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 124} ] }
,
  {   "ip": "127.0.0.2",   "timestamp": "1660632255", "ports": [ {"port": 3306, "proto": "tcp", "status": "close", "reason": "syn-ack", "ttl": 124} ] }

]
```
#### 4、从fofa搜索ip开放端口扫描模式：
````
./nmScan_go -m fofa -m ip.txt -oT
扫描目标格式如下：
218.x.x.x
182.x.x.x
47.x.x.x
221.x.x.x
````
#### 运行截图
![image-1.png](https://github.com/rambleZzz/nmScan_go/blob/main/README/image-1.png)  
![image-2.png](https://github.com/rambleZzz/nmScan_go/blob/main/README/image-2.png)   
![image-3.png](https://github.com/rambleZzz/nmScan_go/blob/main/README/image-3.png)  
![image-4.png](https://github.com/rambleZzz/nmScan_go/blob/main/README/image-4.png)  
![image-5.png](https://github.com/rambleZzz/nmScan_go/blob/main/README/image-5.png)    
### 结果输出
#### 1、txt结果输出
-oT表示输出到txt，此参数默认为false,如果需要导出到文本需添加此参数
#### 2、sqlite结果输出
 -oS表示输出到sqlite，此参数默认为true,不加也会输出,如果-oS false表示不输出至sqlite
#### 结果截图
![image-7.png](https://github.com/rambleZzz/nmScan_go/blob/main/README/image-7.png)   
![image-8.png](https://github.com/rambleZzz/nmScan_go/blob/main/README/image-8.png) 
![image-6.png](https://github.com/rambleZzz/nmScan_go/blob/main/README/image-6.png)

### 参考链接 
github.com/Ullaakut/nmap/v2
https://github.com/shadow1ng/fscan  
https://github.com/wgpsec/ENScan_GO
