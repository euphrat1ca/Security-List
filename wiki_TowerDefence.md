# 系统防御体系
- https://github.com/baidu/AdvBox    --Advbox是支持多种深度学习平台的AI模型安全工具箱，既支持白盒和黑盒算法生成对抗样本，衡量AI模型鲁棒性，也支持常见的防御算法
- https://github.com/OWASP/SecureTea-Project    --当有人私自触碰电脑鼠标或触摸板，进行报警
## 系统管理
- https://docs.microsoft.com/zh-cn/sysinternals/    --微软系统管理组件套，autorun（自启动）、Process Explorer（进程管理定位加强）、procmon、procdump、sqldumper（监控应用程序CPU异常动向, 异常时生成crash dump文件）、Process Monitor。G:/microsoft/ProcDump-for-Linux;--
- https://bitsum.com/    --系统优化工具，主要功能是基于其特别的算法动态调整各个进程优先级以实现为系统减负的目的，可用来监视进程动作。
- https://www.crystalidea.com/uninstall-tool    --Windows卸载，附带软件安装跟踪。P:/CCleaner;--
- http://emptyloop.com/unlocker/    --右键扩充工具，通过删除文件和程序关联的方式解除文件的占用，在解除占用时不会强制关闭占用文件进程。
### 系统文件监控
- https://www.zynamics.com/software.html    --BinDiff发现反汇编代码中的差异和相似之处。支持x86、MIPS、ARM/AArch64、PowerPC等架构进行二进制文件对比
- http://www.beyondcompare.cc/xiazai.html    --Beyond Compare是Scooter Software推出的文件比较工具。主要用于比较两个文件夹或者文件并将差异以颜色标记，比较的范围包括目录，文档内容等
- https://github.com/target/strelka    --Py3。文件变化实时监控。
### 系统注册表管理
- https://sourceforge.net/projects/regshot/    --Regshot是注册表比较工具，通过抓取两次注册表快速比较得出两次注册表的不同之处。
### 系统进程监控
- https://github.com/unknownv2/CoreHook    --C#。基于.NET Core运行时实现的Windows HOOK库
- http://www.xuetr.com/    --PC Hunter是一个驱动级的系统维护工具，能够查看各种Windows的各类底层系统信息，包括进程、驱动模块、内核、内核钩子、应用层钩子，网络、注册表、文件、启动项、系统杂项、电脑体检等。pchunter。P:/火绒剑系统管理;--
- https://github.com/mohuihui/antispy    --C,C++。枚举32位系统中隐藏至深的进程、文件、网络连接、内核对象等，并且也可以检测用户态、内核态钩子.
- https://github.com/draios/sysdig    --C++。系统活动监控，捕获和分析应用程序。它具有强大的过滤语言和可自定义的输出，以及可以使用称为chisels 的Lua脚本扩展的核心功能。goodjob,6k。W:sysdig.com;--
- https://github.com/osquery/osquery    --C++。Facebook创建的SQL驱动操作系统检测和分析工具，支持像SQL语句一样查询系统的各项指标，如运行进程/加载内核模块/网络连接/浏览器插件/硬件事件/文件哈希等。```osquery.io```。14k。
- https://www.portablesoft.org/    --可以Unlock占用文件的进程，查看文件或文件夹被占用的情况，内核模块和驱动的查看管理，进程模块的内存dump等工具
- https://github.com/processhacker/processhacker    --C。Process hacker 监控系统资源、内存以及模块信息、软件调试，管理进程
- https://github.com/zodiacon/ProcMonXv2    --C++。Process Monitor Windows内核监控。
- https://github.com/rabbitstack/fibratus    --Py。对Windows内核活动-进程/线程创建和终止，上下文转换，文件系统I/O，寄存器，网络活动以及DLL加载/卸载等进行捕捉。
- https://github.com/kkamagui/shadow-box-for-arm    --C,Py。ARM架构Linux系统监控，*shadow-box-for-x86*架构系统监控。
- https://github.com/DominicBreuker/pspy    --Go。Linux下可使用非root权限，对系统进程命令运行监控。GoodJob。

## 主机威胁防御
- https://github.com/ossec/ossec-hids    --C。基础hids（主机入侵检测）、SIM/SIEM、堡垒机为一体的监控系统。
- https://documentation.wazuh.com    --C。开源C/S架构主机入侵检测系统网络安全平台，支持日志收集、文件监控、恶意软件检测、漏洞基线检测等功能，集成OpenSCAP、Elastic Stack。goodjob。
- https://www.elastic.co/cn/security    --Elastic Security SIEM威胁检测与端点防护和响应。P:Limitless XDR --SIEM和 Endpoint Security 功能;--
- https://github.com/elastic/detection-rules    --Elastic Security主机防护规则。
- https://github.com/baidu/openrasp    --Runtime Application Self-Protection实时应用自我保护，支持语言栈定制。goodjob。G:/baidu-security/openrasp-iast --IAST扫描器交互式漏洞挖掘;--
- http://www.jrasp.com/    --Java Runtime Application Self-Protection。G:jvm-rasp;--
- https://github.com/bytedance/Elkeid    --字节跳动安全团队开源自研HIDS，Elkeid Agent，Elkeid Driver，Elkeid RASP，Elkeid Server，Elkeid HUB组成，execve、定制化的syscall hook等内核态信息。P:AuditD是Linux自身的审计系统中的一个用户态工具，将SYSCALL调用、文件读写操作等行为记录写入磁盘，AuditD支持多种监听事件的配置和定制，实践中常用于作为反入侵/违规审计的数据源;G:/EBWi11/AgentSmith-HIDS;--
- https://github.com/ysrc/yulong-hids    --Go。驭龙HIDS入侵检测系统，Agent/Daemon/Server/Web。
- https://labs.360.cn/malwaredefender/    --HIPS (主机威胁防护)，用户可以自己编写规则来防范病毒、木马的侵害，同时Malware Defender提供了很多有效的工具来检测和删除已经安装在计算机系统中的恶意软件。
- https://github.com/0Kee-Team/WatchAD    --Py。360 信息安全中心 0kee Team 域安全入侵感知系统，能够及时准确发现高级域渗透活动，检测覆盖内网攻击杀伤链大部分手法。P:天眼;P:天擎;--
- https://github.com/Neo23x0/Loki    --IOC和APT应急响应入侵痕迹扫描器
- https://github.com/felixweyne/ProcessSpawnControl    --PS。对恶意程序进行检测与监控。
- https://github.com/crowdsecurity/crowdsec    --Go。Linux下主机入侵检测，lua模块，nginx反代，一键部署。webGUI。goodjob。
- https://github.com/TheKingOfDuck/FileMonitor    --py。基于watchdog的文件监视器变化监控（代码审计辅助）。testjob。
- https://github.com/grayddq/HIDS    --基于osquery的主机信息监控。

## 终端安全响应
- http://edr.sangfor.com.cn/    --深信服SfAntiBotPro内存检索工具，可以根据输入的字符串快速检索计算机内存，输出包含该字符串的进程信息进行恶意域名检测
- http://edr.topsec.com.cn/    --天融信EDR终端威胁防御系统。
- http://techtalk.comodo.com/2020/09/19/open-edr-components/    --开放式EDR组件。techteach。G:/ComodoSecurity/openedr;--
- https://github.com/DasSecurity-Labs/AoiAWD    --PHP。Linux下CTF AWD轻量级EDR系统，支持flag替换。webgui。goodjob。G:/0xrawsec/whids;--
- https://github.com/olafhartong/ThreatHunting/    --Py。基于Splunk插件的EDR系统。公众号:打造MITRE ATT&CK矩阵检测规则edr系统;--

## 网络威胁防御
- https://github.com/Security-Onion-Solutions/security-onion    --Security Onion洋葱安全入侵检测系统。基于Ubuntu涵盖ELK\Snort\Suricata\Bro等组件，作为传感器分布在网络中监控多个VLAN和子网。ids kali系统类。
- https://github.com/StamusNetworks/SELKS    --基于Debian的入侵检测系统，包含Suricata IDPS/MOLOCH/ELK/Scirius。
- https://www.anquanke.com/post/id/167620    --威胁情报专栏：威胁情报标准——结构化威胁信息表达式（STIX）
### 隐蔽隧道检测
- https://www.freebuf.com/articles/network/247810.html    --针对HTTPS加密流量的Webshell检测研究（冰蝎全系列有效）
- https://github.com/We5ter/Flerken    --py。跨平台混淆命令检测的解决方案。
- https://www.freebuf.com/articles/network/244094.html    --NIDS（suricata）中的DNS混淆加密检测。techteach。
### 网络入侵检测
- https://github.com/ptresearch/AttackDetection    --suricata、snort规则更新。G:/Canon88/suricata-scripts;--
- https://github.com/OISF/suricata    --C。IDS\IPS\NSM安全工具，兼容Snort插件。
- https://github.com/iqiyi/qnsm    --C/C++。爱奇艺基于dpdk与Suricata的旁路部署全流量引擎，集成DDOS检测和IDPS模块。
- https://www.elastic.co/cn/blog/discovering-anomalous-patterns-based-on-parent-child-process-relationships    --TechTeach。基于父子进程关系来检测异常模式，使用机器学习中的异常模型来检测攻击者。
### 网络威胁NTA
- https://github.com/BloodHoundAD/BloodHound    --PS。使用图论进行内网信息域内关系与细节整理，作为DEFCON 24的免费开源工具发布。通过脚本导出域内的session、computer、group、user等信息，入库后进行可视化分析域成员和用用户关系。goodjob。
- https://www.4hou.com/penetration/5752.html    --Intro。域渗透提权分析工具 BloodHound 1.3 中的ACL攻击路线。
- https://github.com/odedshimon/BruteShark    --网络取证分析工具（NFAT），构建网络地图、提取密码数据。
- https://github.com/vletoux/pingcastle    --Py。AD域信息威胁等级测试。
- https://www.netresec.com/?page=Networkminer    --//网络取证分析工具，对比GrassMarlin。通过嗅探或者分析PCAP文件可以侦测到操作系统，主机名和开放的网络端口主机，可解析http 2与TLS加密。P:网络取证与监控caploader 流量捕获;P:polarproxy tls加密流量代理;--
- https://github.com/zeek/zeek    --C++。bro的升级版，主要用于对链路上所有深层次的可疑行为流量进行安全监控，为网络流量分析提供了一个综合平台，特别侧重于语义安全监控。goodjob。
### 流量协议分析
- https://mp.weixin.qq.com/s/w6nvyYFsTaZqE2AcoTvEIA    --公众号：攻守道—流量分析的刀光剑影。wireshark操作指令。
- https://github.com/wireshark/wireshark    --Lua。议解析流量分析还原，可通过Windows变量名“SSLKEYLOGFILE”的变量导出目标网站证书，进行密钥导入到Wireshark流量解析。
- http://www.colasoft.com.cn/download.php    --科来网络分析系统，ping/mac地址扫/数据包重放/数据包生成。
- https://github.com/brimsec/brim    --JS。全流量pcap包分析。支持zeek格式转换，结合wireshark对流量进行分析。goodjob。WebGUI。
- https://github.com/aol/moloch    --全流量捕获分析系统，capture/viewer/elasticsearch。GreatJob。
- https://github.com/eciavatta/caronte    --JS,Go。全流量分析工具。
- https://github.com/cisco/mercury    --C++。基于AF_PACKET和TPACKETv3网络元数据捕获和分析，pmercury指纹识别。
- https://github.com/0x4D31/fatt    --Py。利用tshark对流量进行解析
- https://github.com/netxfly/xsec-traffic    --Go。轻量级的恶意流量分析程序，包括传感器sensor和服务端server 2个组件。
- https://gitee.com/qielige/openQPA    --协议分析软件QPA的开源代码，特点是进程抓包、特征自动分析。
- https://github.com/adulau/ssldump    --C。SSLv3/TLS网络协议分析器。
- http://lcamtuf.coredump.cx/p0f3    --C。p0f升级版被动流量抓取，TCP/http指纹识别
### 流量抓取嗅探
- http://www.tcpdump.org    --网络数据包截获分析
- https://github.com/NytroRST/NetRipper    --支持截获像putty，winscp，mssql，chrome，firefox，outlook，https中的明文密码。
- http://tcpick.sourceforge.net    --TCP流嗅探和连接跟踪工具
- https://github.com/zerbea/hcxdumptool    --从Wlan设备上捕获数据包
- https://www.elifulkerson.com/projects/rawsniff.php    --Windows下流量镜像工具。W:netresec.com/?page=RawCap;--
- https://github.com/nospaceships/raw-socket-sniffer    --C。PS。无需驱动抓取Windows流量。
- https://github.com/tomer8007/chromium-ipc-sniffer    --嗅探chromium进程之间通讯。
### 流量镜像重放
- https://github.com/didi/sharingan    --Go。流量录制，流量重放。
- https://github.com/shramos/polymorph    --支持几乎所有现有协议的实时网络数据包操作框架
- https://github.com/netsniff-ng/netsniff-ng    --C。a fast zero-copy analyzer Linux网络分析器。pcap捕获和重放工具，trafgen数据包生成压测。

## 应用日志分析
- https://github.com/grafana/grafana    --TypeScript,Go。用于可视化大型测量数据的开源程序，提供创建、共享、浏览数据方法与众多功能插件。greatjob。29.5k。
- https://github.com/Cyb3rWard0g/HELK    --Jupyter Notebooks。基于ELK(Elasticsearch, Logstash, Kibana)的日志威胁分析。1K。G:/OTRF/OSSEM;--
- https://developer.ibm.com/qradar/ce/    --IBM QRadar 轻量级日志和流量分析，要求10+250配置。
- http://www.finderweb.net/    --主机、日志、文件管理系统。
- https://github.com/woj-ciech/Danger-zone    --关域名、IP、电子邮件地址关联数据图像可视化输出。
- https://github.com/anbai-inc/AttackFilter    --Logstash 日志安全攻击分析插件
### Web日志分析
- https://wangzhan.qianxin.com/activity/xingtu/    --360星图。P:/LogForensics;W:VirusTotal Graph;--
- http://www.awstats.org/    --开源日志分析系统，将流媒体、ftp、邮件服务器信息图像可视化。
- https://www.goaccess.cc/    --C。全web日志格式类型数据图像可视化分析。
- https://logstalgia.io/    --C++。跨平台数据图像可视化日志分析。
- https://gitee.com/524831546/xlog/    --Go。web访问日志分析工具,可以分析nginx、resin ,tomcat,apache访问日志，然后对访问的ip，流量，响应时间，状态码，URI，浏览器，爬虫进行详细全面的分析展示。
- https://github.com/JeffXue/web-log-parser    --Py。web日志分析工具。
- https://github.com/zhanghaoyil/Hawk-I    --Py。基于无监督机器学习算法从Web日志中自动提取攻击Payload。
- https://github.com/C4o/FBI-Analyzer    --Lua,Go。基于lua虚拟机的Web日志分析系统，插件风格类似ngx-lua，具有拦截、日志传输等模块，秒级加载。G:/C4o/LogFarmer;G:/C4o/IUS;--
- https://github.com/Canop/rhit    --nginx日志分析
### 主机日志分析
- https://github.com/JPCERTCC/LogonTracer    --JS,Py。日本计算机应急团队根据Win登陆记录日志，将关联数据图像可视化，通过neo4j展示分析恶意行为。Github:/Releasel0ck/NetTracer;--
- https://github.com/ahmedkhlief/APT-Hunter    --收集Windows信息分析apt行为。
- http://www.nirsoft.net/utils/computer_activity_view.html/    --LastActivityView是一款电脑操作记录查看器，直接调用系统日志，显示安装软件、系统启动、关机、网络连接、执行exe 的发生时间和路径。
- https://github.com/baronpan/SysmonHunter    --JS。针对att&ck对sysmon日志进行分析可视化展示。G:/jpcertcc/sysmonsearch;--
- https://github.com/olafhartong/sysmon-cheatsheet    --Sysmon操作手册，各id属性含义。G:Sysinternals/SysmonForLinux;--
- https://github.com/olafhartong/sysmon-modular/    --Sysmon配置文件，file/dns/att&ck/系统进程/图片 等分类为归置。G:/SwiftOnSecurity/sysmon-config;G:/ion-storm/sysmon-config;--

## 网关火墙
- https://github.com/0xInfection/Awesome-WAF    --awesome waf
- http://www.safedog.cn/    --安全狗Web服务器网站防护。商业版 社区版。
- http://d99net.net/    --D盾IIS服务器防火墙，webshel查杀。社区版。
- https://github.com/qq4108863/himqtt/    --C。物联网epoll高并发防火墙。
### 防火墙Waf
- https://github.com/evilsocket/opensnitch    --PY,Go。基于QT界面Linux下的应用防火墙。
- https://www.pfsense.org    --PHP。Web防火墙，可配置snort规则。开源版。
- https://github.com/SpiderLabs/ModSecurity    --C。跨平台 WAF engine for Apache/IIS/Nginx etc…。
- https://github.com/klaubert/waf-fle    --ModSecurity Web控制台
- https://github.com/SpiderLabs/owasp-modsecurity-crs    --GO,C。owasp关于ModSecurity等防火墙规则库
- https://github.com/w2sft/BrowserWAF/    --Js。单文件浏览器端WAF。G:/w2sft/ShareWAF_Blance --负载均衡;--
- https://github.com/jx-sec/jxwaf    --Lua。JXWAF(锦衣盾)基于openresty(nginx+lua)开发的web应用防火墙，独创的业务安全防护引擎和机器学习引擎可以有效对业务安全风险进行防护，解决传统WAF无法对业务安全进行防护的痛点。Github:/starjun/openstar;Github:/xsec-lab/x-waf;Github:/loveshell/ngx_lua_waf;Github:/starjun/openstar;--
- https://github.com/Kanatoko/libinjection-Java    --Java。日本语义waf
### 防火墙组件
- https://github.com/koangel/grapeSQLI    --go。基于libinjection的Sql inject & XSS分析程序。
- https://github.com/chaitin/yanshi    --C++。长亭偃师（yanshi），雷池（SafeLine）防火墙核心引擎语义规则模块。
- https://github.com/chaitin/sqlchop-http-proxy    --利用HTTP 反向代理，内置 SQLChop 作为 SQL 注入攻击检测模块，可以拦截 SQL 注入流量而放行正常流量。

## 无线网络防御
- https://github.com/SkypLabs/probequest    --嗅探和显示无线网卡附近的Wifi Probe请求。
- https://github.com/wangshub/hmpa-pi    --在树莓派或路由，利用 Wireshark 分析附近网络 WiFi 设备，当有手机或其它 Wi-Fi 设备在附近时，通过邮件或者微信提醒。
- https://github.com/anwi-wips/anwi    --无线IDS，基于低成本的Wi-Fi模块(ESP8266)
- https://github.com/besimaltnok/PiFinger    --检查wifi是否为"Wifi-Pineapple大菠萝"所开放的恶意热点。
- https://github.com/WiPi-Hunter/PiSavar    --利用PineAP，对于FAKE AP虚假接入点，如"Wifi-Pineapple大菠萝"进行监测。
- https://github.com/SYWorks/waidps    --Py。Linux下WiFi网络防御预警工具。
- https://github.com/SYWorks/waidps    --Py。Linux下无线网络入侵检测工具
## 大数据平台防御
- https://github.com/shouc/BDA    --针对hadoop/spark/mysql等大数据平台的审计与检测
- https://github.com/wavestone-cdt/hadoop-attack-library    --hadoop测试方式和工具集