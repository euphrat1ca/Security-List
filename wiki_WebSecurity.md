# 空间测绘
- https://github.com/nmap/nmap    --Lua。Nmap扫描器具有有强大的脚本引擎框架。greatjob。
- https://github.com/cea-sec/ivre    --Py。网络资产指纹发现，bro/argus/nfdump/p0f/nmap/zmap/masscan/数据库mongoDB。G:/alechilczenko/pwndora;G:/nanshihui/Scan-T;G:/LangziFun/LangNetworkTopology3;G:/LubyRuffy/fofa;--
- https://github.com/zmap/zmap    --C。无状态扫描，可使用C编写扩展模块。censys三件套。
- https://github.com/zmap/zgrab2    --Go。配合zmap/ztag的指纹抓取工具。censys三件套。G:/chichou/grab.js;--
- https://github.com/zmap/zdns    --Go。Fast CLI DNS Lookup Tool。censys三件套。
- https://github.com/zmap/ztag    --Py。对zmap\zgrab产生的数据分析打标签。censys三件套。
- https://github.com/w-digital-scanner/w12scan    --py3。django + elasticsearch + redis(去重+web与w12scan-client通信中间件)网络资产发现引擎，通过WEB API下发任务。boy-hack开发。
- https://hacktech.cn/2021/10/27/net-search-platform-compare/    --网络空间检索平台对比
## 资产端口扫描
- https://github.com/robertdavidgraham/masscan    --C。无状态扫描器。On Windows, or from VMs, it can do 300,000 packets/second. On Linux (no virtualization) it'll do 1.6 million packets-per-second。
- https://paper.seebug.org/1052/    --Intro。从 Masscan, Zmap 源码分析到开发实践。扫描方式socket/libpcap/PF_RING DNA设备/ 三种介绍。
- https://github.com/OffensivePython/Nscan    --Py。类Masscan和Zmap架构。
- https://github.com/angryip/ipscan    --Java。Angry IP Scanner。跨平台界面化端口扫描器,angryip.org。G:/foryujian/yujianportscan;G:/RASSec/RASscan;G:/projectdiscovery/naabu;--
- http://www.advanced-ip-scanner.com    --Advanced IP Scanner Portable端口扫描器。商业版。
## 资产信息搜集
1. https://github.com/lijiejie/EasyPen    --wxpython。bbscan升级版。
- https://github.com/cedowens/SwiftBelt/    --Swift。macOSX系统信息搜集。
- https://github.com/m8r0wn/nullinux    --Py。Linux下内网信息渗透测试工具，可用于通过SMB枚举操作系统信息，域信息，共享，目录和用户。
- https://github.com/trimstray/otseca    --Linux系统审计工具，可以导出系统配置，生成报表
- https://github.com/fdiskyou/hunter    --C++。调用 Windows API 对内网信息搜集。
- https://github.com/skelsec/jackdaw/    --Py。内网信息收集，将域控、域成员信息存储入sqlite数据库，WebGUI。
- https://github.com/FortyNorthSecurity/EyeWitness    --获取目标网站截图、vnc、rdp服务，尝试获取默认凭证。
- https://github.com/lijiejie/BBScan    --Py。网站信息泄漏批量扫描脚本。GoodJob。
- https://github.com/broken5/WebAliveScan    --Py。对目标域名进行快速的存活扫描、标题抓取、目录扫描。welljob。
- https://www.freebuf.com/sectool/109949.html    --小米范资产搜集。goodjob。
- https://github.com/projectdiscovery/httpx/    --Go。网络请求抓取，标题获取等。
- https://github.com/grayddq/PubilcAssetInfo    --Py3。主要目标是以甲方安全人员的视角，尽可能收集发现企业的域名和服务器公网IP资产，如百度云、阿里云、腾讯云等。一个人的安全部。
- https://github.com/Adminisme/ServerScan    --Go。内网横向信息收集的高并发网络扫描、服务探测工具。G:/uknowsec/TailorScan;G:/se55i0n/PortScanner;G:/tengzhangchao/PortScan;--
- https://github.com/xiaoheiwo/GGSCAN    --py。联动nmap、masscan、hydra的快速资产探测工具。G:/sowish/LNScan;G:/dr0op/bufferfly;--
- https://github.com/nray-scanner/nray    --Go。分布式扫描工具，支持ldap\证书扫描。
- https://github.com/lifenjoiner/nbtscan    --C。NetBIOS协议主机设备发现v1.5.2版本，可显示地址，计算机名称，工作组或域，地址，和公司生产的网络适配器（根据确定的地址）。W:nirsoft.net/utils/netbios_scanner.html;G:/scallywag/nbtscan;--
- https://github.com/royhills/arp-scan    --C。ARP协议主机设备发现。
- https://github.com/Rvn0xsy/OXID-Find    --Py。通过OXID解析器获取Windows指定IP/C段远程主机上网卡地址。G:/r35tart/GetIPinfo;G:/uknowsec/SharpOXID-Find;P:netdiscover;--
- https://github.com/projectdiscovery/mapcidr    --Go。子网CIDR扫扫描器。
- https://github.com/cckuailong/hostscan    --Go。ip扫描host碰撞
### 资产指纹识别
- https://github.com/AliasIO/Wappalyzer    --JS。网站指纹识别。资产库，Chrome扩展。5k。G:/l3m0n/whatweb;G:/Lucifer1993/cmsprint;G:/boy-hack/gwhatweb;G:/zerokeeper/WebEye;n4xh4ck5/CMSsc4n;G:/Ms0x0/Dayu;G:/0xbug/Howl;G:/jekyc/wig;G:/tanjiti/FingerPrint;G:/ywolf/F-MiddlewareScan;G:/1N3/Sn1per;--
- https://github.com/HA71/WhatCMS    --Bash。基于Whatcms.org API进行CMS检测和漏洞利用脚本。
- https://github.com/urbanadventurer/whatweb    --Ruby。Web指纹识别。goodjob。G:/Rvn0xsy/FastWhatWebSearch;G:/ggusoft/inforfinder;--
- https://github.com/zhzyker/dismap    --Go。识别 Web 指纹信息，定位资产类型。G:/s0md3v/Arjun    --Py3。HTTP参数信息挖掘工具。simple。
- https://github.com/mozilla/ssh_scan    --服务器ssh配置信息扫描。
- https://github.com/salesforce/jarm    --Python。识别传输层安全性（TLS）指纹，对具有相同TLS配置服务标记，集成于空间测绘资产标签。goodjob。G:/rbsec/sslscan;--
- https://github.com/mozilla/cipherscan    --目标主机服务ssl类型识别。
- https://github.com/EnableSecurity/wafw00f    --WAF产品指纹识别
### 资产&漏洞管理
- https://www.shodan.io/    --老牌空间测绘。W:zoomeye.org;W:censys.io/;W:oshadan.com;W:spyse.com;--
- https://www.fofa.so    --白帽汇空间测绘。G:/zsdevX/DarkEye;G:/tangxiaofeng7/Fofa-collect;G:/uknowsec/Fofa-gui;G:/x51/fofahelper;--
- https://github.com/ShiHuang-ESec/EHole    --EHole(棱洞)-红队重点攻击系统指纹探测工具，fofa api。goodjob。
- https://github.com/knownsec/Kunyu    --Py3。基于zoomeye企业资产信息搜集
- https://github.com/x0day/Multisearch-v2    --Bing、google、360、zoomeye等搜索引擎聚合搜索，可用于发现企业被搜索引擎收录的敏感资产信息。
- https://github.com/zhaoweiho/SecurityManageFramwork    --PY3。SecurityManageFramwork-SeMF基于django2，包含资产管理，漏洞管理，账号管理，知识库管、安全扫描自动化功能模块，可用于企业内部的安全管理。goodjob。G:/ATpiu/asset-scan;--
- https://github.com/infobyte/faraday    --协作渗透测试和漏洞管理平台
- https://github.com/DefectDojo/django-DefectDojo    --Py。基于django的漏洞资产管理平台
- https://github.com/creditease-sec/insight    --web界面。宜信安全部开发，集成应用系统资产管理、漏洞全生命周期管理、安全知识库管理三位一体的管理平台
- https://github.com/RASSec/A_Scan_Framework    --漏洞管理、资产管理、任务扫描系统。
- https://github.com/dpaulson45/HealthChecker    --Exchange Server性能运行状况检查器脚本
### 资产&风险预警
- https://github.com/Ascotbe/Medusa/blob/master/README.CN.md    --红队武器库平台，目前包括扫描功能(200+个漏洞)、XSS平台、协同平台、CVE监控等功能。
- https://github.com/opencve/opencve    --漏洞预警，在本地进行CVE漏洞探究。G:/yhy0/github-cve-monitor;--
- https://www.anquanke.com/vul    --安全客GitHub安全类目引擎，基于热度、时间，cve漏洞监控。goodjob。

## 资产扫描检测
- https://www.acunetix.com/web-vulnerability-scanner/    --Acunetix WVS扫描器，AWVS支持win/Linux。商业版。AcuSensor iast 代码审计，支持`java php .net`。
- https://github.com/ysrc/xunfeng    --Py。巡风采用web界面，由同程安全开发的网络资产管理、漏洞检测引擎。goodjob。2k。G:/CTF-MissFeng/Watchdog;G:/ody5sey/Voyager;--
- https://gitee.com/awake1t/linglong    --Go。资产巡航扫描masscan+nmap+xray漏洞识别，mysql存储，docker一键启动。
- https://github.com/WyAtu/Perun    --Py2。乙方安服、渗透测试人员和甲方RedTeam红队人员的网络资产漏洞扫描器/扫描框架。goodjob。G:/ywolf/F-NAScanG:/flipkart-incubator/RTA;--
- https://github.com/shadow1ng/fscan    --Go。内网扫描工具。goodjob。
- https://www.ibm.com/us-en/marketplace/appscan-standard    --IBM漏洞扫描器，Glass Box iast 代码审计。商业版。
- https://my.oschina.net/9199771/blog/4951572    --Netsparker6 插桩扫描试用记述。iast插桩与流量代理扫描。
- https://www.tenable.com/downloads/nessus    --漏洞扫描器，系统漏洞检测功能突出。商业版，Nessus无IP限制版虚拟机。
- https://github.com/andresriancho/w3af    --Py。老牌Web漏洞网站扫描器。G;Fireflyi/lcyscan;G:/sullo/nikto;--
- https://www.52pojie.cn/thread-134667-1-1.html    --Safe3 Web漏洞扫描系统企业版v10.1 破解版 Crack By Lkou[LCG]。
- https://github.com/euphrat1ca/polar-scan    --易语言。北极熊扫描器。
- https://github.com/euphrat1ca/yeezy-scan    --椰树1.9扫描器。G:/euphrat1ca/WebCruiserWVS;G:/theInfectedDrake/TIDoS-Framework;G:/Tuhinshubhra/RED_HAWK;G:/blackye/lalascan;--
- https://github.com/google/tsunami-security-scanner/    --Java。谷歌海啸漏扫。
- https://github.com/TideSec/WDScanner    --PHP。TideSec开源分布式web漏洞扫描、客户管理、漏洞定期扫描、子域名枚举、端口扫描、网站爬虫、暗链检测、坏链检测、网站指纹搜集、专项漏洞检测、代理搜集及部署等功能。G:/blackye/BkScanner;G:/Arachni/arachni;--
- https://github.com/m4ll0k/Spaghetti    --Web应用扫描器，支持指纹识别、文件目录爆破、SQL/XSS/RFI等漏洞扫描，也可直接用于struts、ShellShock等漏洞扫描。G:/0xInfection/TIDoS-Framework;G:/secdec/adapt;G:/Ekultek/Zeus-Scanner;G:/v3n0m-Scanner/V3n0M-Scanner;G:/RASSec/pentestEr_Fully-automatic-scanner;--
- https://github.com/az0ne/AZScanner    --WebGui。自动漏洞扫描器，子域名爆破，端口扫描，目录爆破，常用框架漏洞检测。G:/Skycrab/leakScan;G:/MiniSafe/microweb;G:/dermotblair/webvulscan;G:/zhangzhenfeng/AnyScan;G:/Canbing007/wukong-agent;G:/jeffzh3ng/InsectsAwake;--
- https://github.com/0xsauby/yasuo    --Ruby。扫描主机第三方web应用服务漏洞。G:/yangbh/Hammer;G:/viraintel/OWASP-Nettacker;G:/flipkart-incubator/watchdog;G:/m4ll0k/Galileo;G:/samhaxr/hackbox;G:/m4ll0k/WAScan;G:/jiangsir404/S7scan;G:/hatRiot/clusterd;G:/tulpar/tulpar;G:/UltimateHackers/Striker --绕过Cloudflare;--
- https://github.com/0x4D31/salt-scanner    --Py。基于Salt Open以及Vulners Linux Audit API的linux下扫描器，支持与JIRA项目管理、slack通讯框架结合使用。
- https://github.com/taipan-scanner/Taipan    --WebGui。基于F#与C#的扫描器。G:/iceyhexman/onlinetools;--
- https://github.com/tlkh/prowler    --一款基于Raspberry Pi Cluster 的网络漏洞扫描工具。
- https://github.com/gyoisamurai/GyoiThon    --Py。使用深度学习的渗透测试工具，从每次扫描数据中学习，扫描越多，软件检测精准度越高。
- https://github.com/TideSec/Mars    --Py。基于Docker资产检测工具联动（集成awvs、创宇Pocsuite、nmap、hydra）。G:/0xbug/Biu-framework;G:/jeffzh3ng/Fuxi-Scanner;--
### 资产漏洞测试
- https://gobies.org/    --Goby是白帽汇资产风险管理工具。端口、服务、截图、弱口令测试。goodjob。W:rumble.run;G:/grayddq/PublicMonitors;--
- https://github.com/k8gege/Ladon    --C#。大型内网渗透扫描器&Cobalt Strike插件支持，横向拓展。goodjob。
- https://github.com/k8gege/LadonGo    --Go。渗透扫描器框架。goodjob。
- https://github.com/knownsec/pocsuite3    --Py3。知道创宇维护的一个规范化Web 安全POC/EXP利用框架。goodjob,2K。G:/zhzyker/vulmap;G:/orleven/Tentacle;--
- https://github.com/Lucifer1993/AngelSword    --Py3。插件式漏洞识别，包含300+系统、Web、工控等漏洞poc。Github:/POC-T;Github:/btScan;Github:/osprey;Github:/pocscan;Github:/TangScan;Github:/Beebeeto-framewor;G:/vulscanteam/vulscan;G:/boy-hack/w9scan;G:/dhondta/sploitkit;G:/PowerScript/KatanaFramework;G:/M4cs/BabySploit;--
- https://github.com/opensec-cn/kunpeng    --Go。漏洞POC检测框架，可以动态链接库的形式提供各种语言调用
- https://github.com/projectdiscovery/nuclei    --Go。基于HTTP请求模板的可配置主动扫描探测工具，类似xray架构poc。goodjob。
- https://github.com/iSafeBlue/TrackRay    --Java。溯光是一个开源的插件化渗透测试框架，框架自身实现了漏洞扫描功能，并集成了知名安全工具：Metasploit、Nmap、Sqlmap、AWVS 等，支持插件编写。G:/Lucifer1993/SatanSword;--
- https://github.com/euphrat1ca/exploitpack    --OracleJava。ExploitPack是一款漏洞利用框架，包含超过38，000+ exploits。商业版。Web:exploitpack.com;--
- https://github.com/Fplyth0ner-Combie/Bug-Project-Framework    --易语言。降龙核工业交响曲bug project framework漏洞框架。NoUpdate。
### 资产被动检测
- https://github.com/c0ny1/passive-scan-client    --Burp插件。被动扫描流量转发插件。
- https://github.com/chaitin/xray    --Go。洞鉴被动代理主动扫描，插件化配置。社区版。goodjob。W:xz.aliyun.com/t/7047;G:/ox01024/Xray_and_crwlergo_in_server;G:/timwhitez/crawlergo_x_XRAY;G:/piaolin/fofa2Xray;--
- https://github.com/w-digital-scanner/w13scan    --Py3。boy-hack被动扫描器Passive Security Scanner。W:x.hacking8.com;G:/netxfly/passive_scan;G:/swisskyrepo/DamnWebScanner;--
- https://github.com/netxfly/Transparent-Proxy-Scanner    --Go。基于vpn和透明代理的web漏洞扫描器，数据库存储mongodb。
- https://github.com/cloudtracer/paskto    --js。基于Nikto扫描规则的被动式路径扫描以及信息爬虫。G:/secrary/EllaScanner;--

# Web安全检测
- https://github.com/zaproxy/zaproxy    --Java。The OWASP ZAP core project出品的综合性渗透测试工具。支持流量代理、请求重放和可扩展性。greatjob,6k。
- https://github.com/TrojanAZhen/BurpSuitePro-2.1    --BurpSuite 1.7.27/2.1 Pro 和谐版本。G:/euphrat1ca/PRUBUnlimitedre;--
- https://github.com/yaklang/yakit    --TypeScript。Yak语言网络安全单兵工具。
- https://portswigger.net/research/web-cache-entanglement    --Web缓存投毒的新途径
- https://github.com/Bo0oM/PHP_imap_open_exploit    --利用imap_open绕过php exec函数禁用
- https://github.com/18F/domain-scan    --针对域名及其子域名的资产数据检测／扫描，包括http/https检测。
- https://github.com/jcesarstef/dotdotslash    --目录遍历漏洞测试
- https://paper.seebug.org/1148/    --RFI 巧用 WebDAV 绕过 URL 包含限制 Getshell。远程文件包含漏洞利用。
- https://github.com/lz520520/railgun    --GUI界面的渗透工具。goodjob。G:/kuiguansec/rcetool;--
## 前端漏洞利用
- https://github.com/ticarpi/jwt_tool    --Py。json web token的检测。G:/lmammino/jwt-cracker;--
- https://github.com/dienuet/crossdomain    --Py。CORS（Cross-Origin Resource Sharing, 跨域资源共享）漏洞扫描器，支持读取aquatone结果，绕过origin安全设置。
- https://www.jianjunchen.com/post/cors安全部署最佳实践/    --intro。CORS域配置错误，CORScanner跨域解析漏洞扫描器。G:/chenjj/CORScanner;--
- https://github.com/MichaelStott/CRLF-Injection-Scanner    --Py3。CRLF injection列表。
- https://github.com/dwisiswant0/crlfuzz    --CRLF注入漏洞扫描。G:/rudSarkar/crlf-injector;--
- https://github.com/m3liot/shcheck    --用于检查web服务的http header的安全性。
- https://github.com/m101/hsploit    --Rust。HEVD 漏洞利用程序。
- https://github.com/coffeehb/SSTIF    --SSTI (服务器模板注入) 漏洞的半自动化工具。
- https://github.com/tijme/angularjs-csti-scanner    --探测客户端AngularJS模板注入漏洞工具。
- https://github.com/epinna/tplmap    --SSTI (服务器模板注入) 漏洞检测与利用工具
- https://github.com/deneme056/CJExploiter    --支持拖放功能的点击劫持漏洞利用工具。
### 抓包代理调试
- https://www.telerik.com/fiddler    --C#。Fiddler4 Free Web Debugging Proxy。Github:/x-Ai/BurpUnlimitedre;W:charlesproxy.com 青花瓷;P:/soft.125.la --精易助手;G:/jakubroztocil/httpie;--
- https://github.com/MegatronKing/HttpCanary    --JS。基于NetBare的安卓移动端抓包代理工具。welljob。
- https://www.0daydown.com/03/33647.html    --IEInspector HTTP Analyzer 进程注入SSL解密。
### SSL/TLS安全
- https://github.com/drwetter/testssl.sh    --Bash。开箱即用，全ssl安全测试，可输出报告。
- https://github.com/hahwul/a2sv    --SSL漏洞扫描，包括OpenSSL心脏滴血漏洞\CSS注入\SSLv3 POODLE等
- https://github.com/nabla-c0d3/sslyze    --Py3。SSL/TLS server扫描器
### CSRF跨站请求伪造利用
- https://www.owasp.org/index.php/File:CSRFTester-1.0.zip    --java。csrf验证工具
- https://github.com/d0nutptr/sic    --Rust。CSS注入，csrf攻击
- https://github.com/UltimateHackers/Blazy    --支持测试 CSRF，Clickjacking，Cloudflare and WAF的弱口令探测器
### SSRF服务端请求伪造
- http://blog.safebuff.com/2016/07/03/SSRF-Tips/    --ssrf漏洞利用手册
- https://github.com/random-robbie/ssrf-finder/    --go。ssrf漏洞检测
- https://github.com/swisskyrepo/SSRFmap    --Py。检测ssrf漏洞
- https://github.com/tarunkant/Gopherus    --Py。利用gopher协议（早期从远程服务器上获取数据的协议）生成ssrf payload执行rce。
- https://www.anquanke.com/post/id/145519/    --intro。浅析SSRF原理及利用方式。gopher、dict、file、http/s协议利用
### XXE解析漏洞
- https://thief.one/2017/06/20/1/    --浅谈XXE漏洞攻击与防御
- https://github.com/BuffaloWill/oxml_xxe    --Ruby。XXE漏洞利用模块生成。
- https://github.com/orf/xcat    --py3。xpath注入漏洞检测利用
- https://github.com/enjoiz/XXEinjector/    --Ruby。外部实体注入漏洞xxe检测利用

## 命令执行注入
- https://github.com/payloadbox/command-injection-payload-list    --命令执行注入列表。goodjob。
- https://github.com/commixproject/commix    --Py。命令注入漏洞扫描
- https://github.com/ewilded/shelling    --Java。burp拓展，OS命令注入有效负载生成器，关于命令注入的解决方案防御手段。
- https://hackingiscool.pl/cmdhijack-command-argument-confusion-with-path-traversal-in-cmd-exe/    --CMD Hijack，命令执行截断执行，配合powershell（带-enc执行）、mshta等方法。
### XSS跨站脚本利用
- https://xsspt.com/index.php?do=blist    --乌云xss学习。
- https://github.com/UltimateHackers/AwesomeXSS    --XSS Awesome系列。
- http://www.xss-payloads.com    --xss工具包、资料、payload导航站。
- https://www.slideshare.net/GarethHeyes/xss-magic-tricks    --burpsuite团队总结xss知识点。
- https://portswigger.net/web-security/cross-site-scripting/cheat-sheet    --跨站脚本（XSS）备忘录，收集了大量的XSS攻击向量，包含了各种事件处理、通讯协议、特殊属性、限制字符、编码方式、沙箱逃逸等技巧。
- https://github.com/heroanswer/XSS_Cheat_Sheet_2020_Edition    --XSS Payload 使用场景。goodjob。G:/ismailtasdelen/xss-payload-list;--
- https://somdev.me/21-things-xss/    --XSS的21个扩展用途。
- https://github.com/NytroRST/XSSFuzzer    --根据特定标签生成xss payload。
- https://github.com/evilcos/xssor2    --xss利用辅助工具。余弦。
### XSS检测辅助
- https://github.com/s0md3v/XSStrike    --Py3。识别、绕过WAF的XSS扫描器。
- https://github.com/hahwul/XSpear    --Ruby。Powerfull XSS Scanning and Parameter analysis tool&gem。G:/0x584A/fuzzXssPHP;G:/Damian89/xssfinder;G:/chuhades/xss_scan;G:/shogunlab/shuriken;--
- https://github.com/raz-varren/xsshell    --Go。利用xss返回JS交互shell。G:/UltimateHackers/JShell;--
- https://github.com/shawarkhanethicalhacker/BruteXSS    --XSS暴力注入参数扫描器。
- https://github.com/1N3/XSSTracer    --CRLF、XSS、点击劫持扫描器。
- https://github.com/BlackHole1/autoFindXssAndCsrf    --自动化检测页面是否存在XSS和CSRF漏洞的浏览器插件。
- https://github.com/stamparm/DSXS    --支持GET、POST方式的高效XSS扫描器
- https://github.com/bsmali4/xssfork    --Py。利用无头浏览器进行xss测试，kali下载PhantomJS驱动到目录"thirdparty/phantomjs/Linux"。
- https://github.com/riusksk/FlashScanner    --flash xss扫描。
- https://www.anquanke.com/post/id/263107    --DOM XSS 存储型XSS自动检测与验证模型。G:/AsaiKen/dom-based-xss-finder;--
### XSS漏洞利用平台框架
- https://github.com/beefproject/beef    --JS,Ruby。BeEF跨平台Web浏览器渗透测试工具。
- https://xss.fbisb.com/    --在线XSS利用平台，xss练习靶场。W:xsshs.cn;xss.wtf;xsspt.com;xs.ax;--
- https://github.com/firesunCN/BlueLotus_XSSReceiver    --JS,PHP。蓝莲花战队XSS数据接收平台（无SQL版）。GOODJOB。
- https://github.com/euphrat1ca/XssPowerByTools    --PHP。XSS平台课程设计。simple。
- https://github.com/AntSwordProject/ant    --Nodejs。蚁逅@1.0，实时上线的 XSS 盲打平台。
- https://github.com/BlackHole1/WebRtcXSS    --PHP。基于thinkphp框架，利用webrtc进行自动化XSS入侵内网平台。
- https://github.com/samdenty99/injectify    --TS,JS。利用xss在网站执行mitm攻击。
### 数据库利用
- https://github.com/sqlmapproject/sqlmap    --Py。数据库注入。GREATJOB。G:/m4ll0k/Atlas --tamper脚本测试;--
- https://github.com/SafeGroceryStore/MDAT    --sql综合利用工具(sqltools)，命令执行、文件管理等功能。goodjob。
- https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/    --sql注入sheet表。
- https://sqlwiki.netspi.com/    --你要的sql注入知识点都能找到
- https://github.com/kevins1022/SQLInjectionWiki    --一个专注于聚合和记录各种SQL注入方法的wiki
- https://sinister.ly/Thread-SQLi-Dumper-v-8-5-crack    --SQLi Dumper基于搜索引擎的自动化注入利用工具。GoodJob
- https://github.com/ron190/jsql-injection    --Java。SQL注入工具。GOODJOB。
- https://github.com/shack2/SuperSQLInjectionV1    --C#。超级SQL注入工具【SSQLInjection】。GOODJOB。
- https://www.52pojie.cn/thread-80225-1-1.html    --Pangolin Professinal Edition 3.2.4.1132 CracKed By Hmily[LCG]。白帽汇NOSEC注入工具。NoUpdate。
- https://www.52pojie.cn/forum.php?mod=viewthread&tid=103057    --Havij v1.151 Pro CracKed By Hmily[LCG]。印度ITSecTeam注入工具。NoUpdate。
- https://github.com/Neohapsis/bbqsql    --SQL盲注利用框架
- https://github.com/m8r0wn/enumdb    --MySQL和MSSQL利用工具后期爆破、搜索数据库并提取敏感信息。
- https://github.com/PaulSec/HQLmap    --Hibernate DAO设计(Data Access Object) HQL注入
- https://github.com/FSecureLABS/N1QLMap    --N1QL注入工具
### 数据库利用MSSQL
- https://www.anquanke.com/post/id/86011    --【技术分享】MSSQL 注入攻击与防御。sql server漏洞利用。
- https://github.com/NetSPI/PowerUpSQL    --Powershell。的sqlserver测试框架
- https://github.com/Mayter/mssql-command-tool    --Go。mssql连接工具，sqlserver利用。
- http://www.4hou.com/system/14950.html    --Intro。利用PowerUpSQL，渗透测试技巧：绕过SQL Server登录触发器限制。
### 数据库利用Mysql注入
- https://github.com/aleenzz/MYSQL_SQL_BYPASS_WIKI    --mysql注入 bypass心得
- https://xz.aliyun.com/t/1491    --Mysql数据库渗透及漏洞利用总结。写shell、udf、mof、注册表、os-shell。
- https://github.com/missDronio/blindy    --MySQL盲注爆破工具
- https://github.com/LoRexxar/Feigong    --针对各种情况自由变化的MySQL注入脚本
- https://github.com/JohnTroony/Blisqy    --Py。用于http header中的时间盲注爆破工具，仅针对MySQL/MariaDB。
- https://github.com/quadcoreside/QuadCore-Web-SQLi-Injecter-DB-Dumper    --PHP。sql注入辅助，数据脱取。
- https://github.com/Hadesy2k/sqliv    --Py3。基于搜索引擎的批量SQL注入漏洞扫描器。G:bambish/ScanQLi;--
### 数据库利用Oracle
- https://mp.weixin.qq.com/s/kxgD0yhPIYoYOSihX9mFcw    --公众号：Oracle命令执行小结
- https://redn3ck.github.io/2018/04/25/Oracle注入-命令执行-Shell反弹/    --Oracle注入 - 命令执行&Shell反弹
- https://www.iswin.org/2015/06/13/hack-oracle/    --Oracle Sql注入利用方法
- https://github.com/jas502n/oracleShell    --rebeyond-oracleShell，数据库命令执行
- https://github.com/quentinhardy/odat    --针对Oracle注入渗透工具
### 数据库利用关系型
- https://github.com/codingo/NoSQLMap    --Py3。针对nosql数据库的注入工具。
- https://github.com/torque59/Nosql-Exploitation-Framework    --NoSQL数据库扫描/爆破工具
- https://github.com/se55i0n/DBScanner    --Py3。常见sql、no-sql数据库资产未授权访问、弱口令检测。simple。
- https://github.com/youngyangyang04/NoSQLAttack    --一款针对mongoDB的攻击工具。G:/Charlie-belmer/nosqli;--
- https://github.com/jas502n/unauthorized-tools    --Py。用于快速探测MongoDB未授权数据库结构，取第一条内容，并统计数据数量。
- https://studio3t.com/download    --MongoDB扫描与连接工具
- https://github.com/stampery/mongoaudit    --MongoDB审计及渗透工具
### 数据库利用云服务
- https://github.com/Turr0n/firebase    --firebase错误配置利用。

## Web越权漏洞
- https://github.com/evilcos/cookiehacker    --Chrome扩展程序。JavaScript document.cookie / Wireshark Cookie 余弦 包括注入、编辑、添加、删除cookie。G:/lfzark/cookie-injecting-tools;--
- https://github.com/ztosec/secscan-authcheck    --java。越权漏洞检测。WebGUI。Github:/portswigger/authz;--
### API安全测试
- https://github.com/shieldfy/API-Security-Checklist    --api开发核对清单。W:xz.aliyun.com/t/2412;--
- https://github.com/GitGuardian/APISecurityBestPractices    --api接口测试checklist。
- https://github.com/microsoft/restler-fuzzer    --REST API模糊测试工具。G:/Fuzzapi/fuzzapi;G:/flipkart-incubator/Astra;--
- https://blog.assetnote.io/2021/04/05/contextual-content-discovery/    --上下文内容发现，api接口收集。G:/assetnote/kiterunner;--
- https://github.com/jayus0821/swagger-hack    --Py。自动化爬取测试swagger接口
### 验证码爆破
- https://github.com/ecjtuseclab/AILoginBlasting    --Py。基于机器学习的登录验证码爆破工具。
- https://code.dsaaaaaaaaaaaaaaaaaaaadwqdqdw101fre.tk:8081/    --post验证码识别接口。
### 上传漏洞利用
- https://github.com/WSP-LAB/FUSE    --py2。基于NDSS 2020上展示的13种文件上传bypass技巧，Linux下文件上传漏洞fuzz工具。配合文件变化监控查找文件上传位置。
- https://github.com/UltimateHackers/Arjun    --扫描网页，使用正则表达式爆破查找隐藏的GET/POST参数
- https://github.com/3xp10it/xupload    --用于自动测试上传功能是否可上传webshell的工具
- https://github.com/gunnerstahl/JQShell    --Py3。CVE-2018-9206 jQuery File Upload利用工具
- https://github.com/destine21/ZIPFileRaider    --burp插件，测试zip文件上传漏洞
- https://github.com/jpiechowka/zip-shotgun    --Py。测试zip文件上传漏洞
- https://github.com/almandin/fuxploider    --Py3。自判定网站类型与可被允许上传的文件格式类型。
### 本地文件包含漏洞
- https://github.com/hvqzao/liffy    --本地文件包含漏洞利用工具
- https://github.com/D35m0nd142/Kadabra    --本地文件包含漏洞扫描和利用工具
- https://github.com/P0cL4bs/Kadimus    --本地文件包含漏洞扫描和利用工具
- https://github.com/D35m0nd142/LFISuite    --本地文件包含漏洞利用及扫描工具，支持反弹shell
- https://github.com/OsandaMalith/LFiFreak    --本地文件包含漏洞利用及扫描工具，支持反弹shell
- https://xz.aliyun.com/t/5535    --session写文件getshell，PHP保存session至文件，Java保存session至内存。


## 网站管理WebShell
- https://github.com/AntSwordProject/antSword    --js。中国蚁剑基于Electron插件式开发。greatjob。
- https://github.com/AntSwordProject/AntSword-Labs    --antSword测试环境
- https://github.com/Chora10/Cknife/pulls    --Java。中国菜刀,greatjob,2K。Github:/SecQuanCknife;gitee.com/9199771/cknife;--
- https://github.com/euphrat1ca/hatchet    --C++。中国大砍刀。
- https://github.com/keepwn/Altman    --.Net,mono。跨平台菜刀。
- https://github.com/euphrat1ca/Behinder    --Java6。“冰蝎”动态二进制加密网站管理客户端。rebeyond，会因为服务器端Java版本产生连接报错。
- https://xz.aliyun.com/t/2744    --Intro。“冰蝎”利用动态二进制加密实现新型一句话木马之Java篇，木马之.NET篇，木马之PHP篇,木马之客户端篇。
- https://github.com/BeichenDream/Godzilla    --Java。哥斯拉shell管理工具。可插件拓展。
- https://github.com/shack2/skyscorpion    --OracleJava。天蝎网站管理。团队协作。
- https://github.com/tengzhangchao/PyCmd    --Py。一句话木马客户端程序。目前支持php、jsp，CS端通信加密
- https://github.com/xl7dev/WebShell    --webshell收集项目。Github:/tennc/webshell;--
### PHP Webshells
- https://github.com/weepsafe/phpshell    --php大马|php一句话|webshell|免杀过狗|
- https://github.com/yzddmr6/webshell-venom    --Py。免杀webshell无限生成工具。
- https://github.com/k4mpr3t/b4tm4n    --PHP。bat.php的webshell初始密码k4mpr3t，可以伪造邮件、ddos，
- https://github.com/dotcppfile/DAws    --PHP。过防火墙webshell，密码`post pass=DAws`
- https://github.com/b374k/b374k    --php。网站管理`默认密码b374k`
- https://github.com/wso-shell/WSO    --PHP。伪装为404界面webshell的文件管理
- https://github.com/DXkite/freebuf-stream-shell    --PHP。使用流包装器实现WebShell。
- https://github.com/UltimateHackers/nano    --php。一句话py生成器
- https://github.com/epinna/weevely3    --Py。利用特定的一句话脚本对网站进行管理G:/nil0x42/phpsploit;G:/wonderqs/Blade;G:/anestisb/WeBaCoo;--
### Java Webshells
- https://github.com/rebeyond/memShell    --Java。可写入java web server内存中的无文件webshell。goodjob。G:/ydnzol/memshell;--
- https://github.com/threedr3am/JSP-Webshells    --jsp webshell 项目收集
- https://github.com/htchina/openfire-webshell    --openfire上传webshell插件
### ASP/X Webshells
- https://github.com/antonioCoco/SharPyShell    --ASP.NET。webshell for C# web application