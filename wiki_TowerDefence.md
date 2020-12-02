# 安全体系防御
- https://shield.mitre.org/attack_mapping/    //ATT&CK主动防御图谱。引导-收集-遏制-检测-扰乱-促进-合法化-实验测试
- https://github.com/Bypass007/Safety-Project-Collection    //甲方安全开源项目清单。welljob。
- https://github.com/baidu/AdvBox    //Advbox是支持多种深度学习平台的AI模型安全工具箱，既支持白盒和黑盒算法生成对抗样本，衡量AI模型鲁棒性，也支持常见的防御算法
- https://github.com/OWASP/SecureTea-Project    //当有人私自触碰电脑鼠标或触摸板，进行报警
## 安全防护建设
- https://github.com/trimstray/iptables-essentials    //IP table常见防火墙规则与命令。P:/Firewall App Blocker 1.7 Windows防火墙快捷操作工具;P:/Linux下防火墙 firewall-cmd;--
- https://github.com/SELinuxProject/selinux/    //C。安全增强型Linux（Security-Enhanced Linux），通过配置增强主机防护安全防御。
- https://github.com/torvalds/linux/blob/master/drivers/net/macsec.c    //C。利用Linux macsec进行链路层流量安全加密。
### 负载均衡建设
- https://github.com/github/glb-director    //负载均衡组件GLB，数据解析使用了dpdk
### DNS防护建设
- https://github.com/mwrlabs/dref    //DNS 重绑定利用框架
- https://github.com/chengr28/Pcap_DNSProxy/blob/master/README.zh-Hans.md    //Pcap_DNSProxy 是一个基于 WinPcap/LibPcap 用于过滤 DNS 投毒污染的工具
### 邮件网关建设
- https://github.com/Janusec/janusec    //Golang。应用安全网关，具备WAF、CC攻击防御、证书私钥加密、负载均衡、统一Web化管理等功能。
- https://github.com/TKCERT/mail-security-tester    //检测邮件防护与过滤系统的测试框架
### DLP建设
- https://github.com/mydlp    //MyDLP是一种简单，简单和开放的DLP（数据丢失预防）解决方案
### 安全防护管理
- https://github.com/tmobile/pacbot    //Java。云平台自动化安全监控工具
- https://www.alienvault.com/products/ossim    //开源开源信息安全管理系统siem安全运维平台解决方案，支持snort\nmap等多种工具插件
### 接口管理
- https://github.com/openitsystem/itops    //PY3,DJANGo。AD\Exchange管理系统。
- https://ln2.io/adminBoard    //Chrome 浏览器插件LN2 for Admin，蓝图局域网资产服务登录口管理。
### 登录管理
- https://github.com/jumpserver/jumpserver    //Python3。开源堡垒机
- https://github.com/cdk8s/tkey    //Java。Token Key 以 OAuth 2.0 标准为接口设计原则的单点登录系统（SSO）
## 系统管理
- https://docs.microsoft.com/zh-cn/sysinternals/    //微软系统管理组件套，autorun（自启动）、Process Explorer（进程管理定位加强）、procmon、procdump、sqldumper（监控应用程序CPU异常动向, 异常时生成crash dump文件）、Process Monitor。G:/microsoft/ProcDump-for-Linux;--
- https://bitsum.com/    //系统优化工具，主要功能是基于其特别的算法动态调整各个进程优先级以实现为系统减负的目的，可用来监视进程动作。
- https://www.crystalidea.com/uninstall-tool    //Windows卸载，附带软件安装跟踪。P:/CCleaner;--
- http://emptyloop.com/unlocker/    //右键扩充工具，通过删除文件和程序关联的方式解除文件的占用，在解除占用时不会强制关闭占用文件进程。
### 系统文件监控
- https://www.zynamics.com/software.html    //BinDiff发现反汇编代码中的差异和相似之处。支持x86、MIPS、ARM/AArch64、PowerPC等架构进行二进制文件对比
- http://www.beyondcompare.cc/xiazai.html    //Beyond Compare是Scooter Software推出的文件比较工具。主要用于比较两个文件夹或者文件并将差异以颜色标记，比较的范围包括目录，文档内容等
- https://github.com/target/strelka    //Py3。文件变化实时监控。
### 系统注册表管理
- https://sourceforge.net/projects/regshot/    //Regshot是注册表比较工具，通过抓取两次注册表快速比较得出两次注册表的不同之处。
### 系统进程监控
- http://www.xuetr.com/    //PC Hunter是一个驱动级的系统维护工具，能够查看各种Windows的各类底层系统信息，包括进程、驱动模块、内核、内核钩子、应用层钩子，网络、注册表、文件、启动项、系统杂项、电脑体检等。pchunter。P:/火绒剑系统管理;--
- https://github.com/mohuihui/antispy    //C,C++。枚举32位系统中隐藏至深的进程、文件、网络连接、内核对象等，并且也可以检测用户态、内核态钩子.
- https://github.com/draios/sysdig    //C++。系统活动监控，捕获和分析应用程序。它具有强大的过滤语言和可自定义的输出，以及可以使用称为chisels 的Lua脚本扩展的核心功能。goodjob,6k。W:sysdig.com;--
- https://github.com/osquery/osquery    //C++。Facebook创建的SQL驱动操作系统检测和分析工具，支持像SQL语句一样查询系统的各项指标，如运行进程/加载内核模块/网络连接/浏览器插件/硬件事件/文件哈希等。```osquery.io```。14k。
- https://www.portablesoft.org/    //可以Unlock占用文件的进程，查看文件或文件夹被占用的情况，内核模块和驱动的查看管理，进程模块的内存dump等工具
- https://github.com/processhacker/processhacker    //C。Process hacker 监控系统资源、内存以及模块信息、软件调试，管理进程
- https://github.com/zodiacon/ProcMonXv2    //C++。Process Monitor Windows内核监控。
- https://github.com/rabbitstack/fibratus    //Py。对Windows内核活动-进程/线程创建和终止，上下文转换，文件系统I/O，寄存器，网络活动以及DLL加载/卸载等进行捕捉。
- https://github.com/open-falcon    //GO,Py。Falco是一款由Sysdig开源的进程异常行为检测工具。它既能够检测传统主机上的应用程序，也能够检测容器环境和云平台（主要是Kubernetes和Mesos）。Github:/falcosecurity/falco;--
- https://github.com/kkamagui/shadow-box-for-arm    //C,Py。ARM架构Linux系统监控，*shadow-box-for-x86*架构系统监控。
- https://github.com/DominicBreuker/pspy    //Go。Linux下可使用非root权限，对系统进程命令运行监控。GoodJob。
## 入侵感知防护
- http://m.imooc.com/article/21236    //快速自检电脑是否被黑客入侵过(Windows版)
- http://www.freebuf.com/articles/system/157597.html    //快速自检电脑是否被黑客入侵过（Linux版）
- http://www.freebuf.com/rookie/179638.html    //服务器入侵溯源小技巧整理
- https://bithack.io/forum/161    //Intro。如何通过一封恶意邮件追踪幕后黑客组织。邮件掉鱼、溯源、攻击者落地
### EDR进程监控
- https://github.com/baidu/openrasp    //基于RASP。Runtime Application Self-Protection，实时应用自我保护，智能针对每个语言定制。testjob,1k。G:/baidu-security/openrasp-iast //IAST交互式漏洞挖掘扫描;--
- https://github.com/EBWi11/AgentSmith-HIDS    //C。Linux下基于Hook system_call的内核级HIDS，特点从内核态获取尽可能全的数据。welljob。斗鱼开源。
- https://github.com/grayddq/HIDS    //基于osquery的主机信息监控。
- https://github.com/ysrc/yulong-hids    //Go。驭龙HIDS入侵检测系统，Agent/Daemon/Server/Web。
### EDR终端防护
- http://edr.sangfor.com.cn/    //深信服SfAntiBotPro内存检索工具，可以根据输入的字符串快速检索计算机内存，输出包含该字符串的进程信息进行恶意域名检测
- http://edr.topsec.com.cn/    //天融信EDR终端威胁防御系统。
- https://labs.360.cn/malwaredefender/    //HIPS (主机入侵防御系统)软件，用户可以自己编写规则来防范病毒、木马的侵害。另外，Malware Defender提供了很多有效的工具来检测和删除已经安装在您的计算机系统中的恶意软件。
- https://github.com/ComodoSecurity/openedr    //C++。开放式EDR组件。
- http://techtalk.comodo.com/2020/09/19/open-edr-components/    //开放式EDR组件。techteach。
- https://github.com/crowdsecurity/crowdsec    //Go。Linux下主机入侵检测，lua模块，nginx反代，一键部署，webGUI。goodjob。
- https://github.com/DasSecurity-Labs/AoiAWD    //PHP。Linux下CTF AWD轻量级EDR系统，支持flag替换。webgui。goodjob。
- https://github.com/0Kee-Team/WatchAD    //Py。360 信息安全中心 0kee Team 域安全入侵感知系统，能够及时准确发现高级域渗透活动，检测覆盖内网攻击杀伤链大部分手法。
- https://github.com/Neo23x0/Loki    //IOC和APT应急响应入侵痕迹扫描器
- https://github.com/olafhartong/ThreatHunting/    //Py。基于Splunk插件的EDR系统。公众号:打造MITRE ATT&CK矩阵检测规则edr系统;G:/ion-storm/sysmon-config;--
- https://github.com/felixweyne/ProcessSpawnControl    //PS。对恶意程序进行检测与监控。
- https://github.com/TheKingOfDuck/FileMonitor    //py。基于watchdog的文件监视器变化监控（代码审计辅助）。testjob。
### 入侵检测防御
- https://github.com/ossec/ossec-hids    //C。基础hids（主机入侵检测）、SIM/SIEM、堡垒机为一体的监控系统。
- https://documentation.wazuh.com    //C。wazuh是C/S架构开源主机入侵检测系统网络安全平台，支持日志收集、文件监控、恶意软件检测、漏洞基线检测等功能，集成OpenSCAP、Elastic Stack。goodjob。
- https://github.com/snort3/snort3    //C++。snort知名NIDS网络入侵检测
- https://github.com/ptresearch/AttackDetection    //suricata、snort规则rules更新。G:/Canon88/suricata-scripts;--
- https://github.com/OISF/suricata    //C。IDS\IPS\NSM安全工具，兼容Snort插件
- https://github.com/iqiyi/qnsm    //C/C++。爱奇艺基于dpdk与Suricata，旁路部署的全流量引擎，集成了DDOS检测和IDPS模块。
- https://github.com/StamusNetworks/SELKS    //基于Debian的入侵检测系统，组件包含Suricata IDPS与ELK和Scirius。
- https://github.com/Security-Onion-Solutions/security-onion    //Security Onion洋葱安全入侵检测系统。基于Ubuntu涵盖ELK\Snort\Suricata\Bro等组件，作为传感器分布在网络中监控多个VLAN和子网。ids kali系统类。
- https://www.elastic.co/cn/blog/discovering-anomalous-patterns-based-on-parent-child-process-relationships    //基于父子进程关系来检测异常模式，使用机器学习中的异常模型来检测攻击者。TechTeach。
- https://www.freebuf.com/articles/network/244094.html    //NIDS（suricata）中的DNS隐蔽隧道检测。techteach。
## 防火墙网关
- https://github.com/0xInfection/Awesome-WAF    //awesome waf
- http://www.safedog.cn/    //安全狗Web服务器网站防护。商业版 社区版。
- http://d99net.net/    //D盾IIS服务器防火墙，webshel查杀。社区版。
- https://github.com/qq4108863/himqtt/    //C。物联网epoll高并发防火墙。
### 防火墙Waf
- https://github.com/evilsocket/opensnitch    //PY,Go。基于QT界面Linux下的应用防火墙。
- http://openresty.org/    //基于 Nginx 与 Lua 的高性能 Web 平台，Waf组件。
- https://www.pfsense.org    //PHP。Web防火墙，可配置snort规则。开源版。
- https://github.com/SpiderLabs/ModSecurity    //C。跨平台 WAF engine for Apache/IIS/Nginx etc…。
- https://github.com/klaubert/waf-fle    //ModSecurity Web控制台
- https://github.com/SpiderLabs/owasp-modsecurity-crs    //GO,C。owasp关于ModSecurity等防火墙规则库
- https://github.com/w2sft/BrowserWAF/    //Js。单文件浏览器端WAF。G:/w2sft/ShareWAF_Blance //负载均衡;--
- https://github.com/jx-sec/jxwaf    //Lua。JXWAF(锦衣盾)是一款基于openresty(nginx+lua)开发的web应用防火墙，独创的业务安全防护引擎和机器学习引擎可以有效对业务安全风险进行防护，解决传统WAF无法对业务安全进行防护的痛点。Github:/starjun/openstar;Github:/xsec-lab/x-waf;Github:/loveshell/ngx_lua_waf;Github:/starjun/openstar;--
### 防火墙组件
- https://github.com/C4o/FBI-Analyzer    //Lua,Go。基于lua虚拟机的Web日志分析系统，插件风格类似ngx-lua，具有拦截、日志传输等模块。G:/C4o/LogFarmer;G:/C4o/IUS;--
- https://github.com/koangel/grapeSQLI    //go。基于libinjection的Sql inject & XSS分析程序。
- https://github.com/chaitin/yanshi    //C++。长亭偃师（yanshi），雷池（SafeLine）防火墙核心引擎语义规则模块。
- https://github.com/chaitin/sqlchop-http-proxy    //利用HTTP 反向代理，内置 SQLChop 作为 SQL 注入攻击检测模块，可以拦截 SQL 注入流量而放行正常流量
### 无线网络入侵检测
- https://github.com/anwi-wips/anwi    //无线IDS，基于低成本的Wi-Fi模块(ESP8266)
- https://github.com/SYWorks/waidps    //Py。Linux下无线网络入侵检测工具
### 大数据平台安全
- https://github.com/shouc/BDA    //针对hadoop/spark/mysql等大数据平台的审计与检测
- https://github.com/wavestone-cdt/hadoop-attack-library    //hadoop测试方式和工具集
## 检测查杀
- https://www.freebuf.com/articles/network/139697.html    //Intro。使用深度学习检测DGA（域名生成算法）。
- https://github.com/mwleeds/android-malware-analysis    //Py。利用机器学习进行恶意Android安卓应用检测。
- https://github.com/EFForg/yaya    //Golang。yara库自动更新。
- https://github.com/KasperskyLab/klara    //卡巴斯基基于Yara的分布式开源恶意软件扫描系统。G:/botherder/kraken;--
- https://github.com/G4rb3n/Script-Ganker    //深信服基于Yara的Linux恶意脚本分析系统。G:/nao-sec/tknk_scanner;--
- https://github.com/netxfly/sec_check    //通过信息采集（账户、连接、端口等），并匹配yara规则进行扫描检测
- https://github.com/viper-framework    //Py3。二进制分析和管理框架
- https://github.com/joxeankoret/pigaios    //基于源代码、二进制文件比对的检测工具
- https://github.com/sfaci/masc    //网站维护与恶意软件检测
- https://github.com/1lastBr3ath/drmine    //自动化检测网页是否包含挖矿脚本的工具
- https://github.com/alexandreborges/malwoverview    //simple。将恶意文件进行快速分类
- https://github.com/Neo23x0/munin    //依据文件 Hash 从在线恶意软件扫描服务提取信息的工具
### 后门检测查杀
- http://www.clamav.net/downloads    //病毒查杀
- https://www.winitor.com/features    //pestudio：恶意软件初始评估工具
- https://github.com/PlagueScanner/PlagueScanner    //python。集成ClamAV、ESET、Bitdefender的反病毒引擎。
- http://rkhunter.sourceforge.net/    //后门排查。系统命令（Binary）检测/包括Md5 校验/Rootkit检测/本机敏感目录、系统配置、服务及套间异常检测/三方应用版本检测。
- http://rootkit.nl/projects/rootkit_hunter.html    //rootkit检测工具
- https://github.com/m4rco-/dorothy2    //木马、僵尸网络分析框架。
- https://github.com/Tencent/HaboMalHunter    //哈勃分析系统，Linux系统病毒分析及安全测试
- http://www.chkrootkit.org/    //后门/僵木蠕/rootkit检测工具
- https://github.com/chaitin/cloudwalker    //Go。长亭牧云服务器安全管理平台，webshell查杀。NoUpdate。
- https://www.shellpub.com/    //河马webshell查杀。社区版跨平台。
- https://github.com/emposha/Shell-Detector    //Webshell扫描工具，支持php/perl/asp/aspx webshell扫描。G:/he1m4n6a/findWebshell;G:/ym2011/ScanBackdoor;Gerevus-cn/scan_webshell;G:/yassineaddi/BackdoorMan;G:/nbs-system/php-malware-finder;G:/emposha/PHP-Shell-Detector;G:/nsacyber/Mitigating-Web-Shells //NSA开源webshell检测;--
- https://www.freebuf.com/articles/network/247810.html    //针对HTTPS加密流量的Webshell检测研究（冰蝎全系列有效）
- https://github.com/Apr4h/CobaltStrikeScan    //C#。针对Windows进程内存进行扫描，查找cobaltstrike DLL注入痕迹
### 混淆命令检测
- https://github.com/We5ter/Flerken    //py。跨平台混淆命令检测的解决方案
## 流量协议操作
- https://mp.weixin.qq.com/s/w6nvyYFsTaZqE2AcoTvEIA    //公众号：攻守道—流量分析的刀光剑影。wireshark操作指令。
- https://github.com/secdev/scapy    //Py。内置了交互式网络数据包处理、数据包生成器、网络扫描器网络发现和包嗅探工具，提供多种协议包生成及解析插件，能够灵活的的生成协议数据包，并进行修改、解析。
- http://tcpick.sourceforge.net    //TCP流嗅探和连接跟踪工具
- https://github.com/zerbea/hcxdumptool    //从Wlan设备上捕获数据包
- https://github.com/nospaceships/raw-socket-sniffer    //C。PS。无需驱动抓取Windows流量。
- https://github.com/tomer8007/chromium-ipc-sniffer    //嗅探chromium进程之间通讯。
### 流量嗅探镜像
- http://www.tcpdump.org    //网络数据包截获分析
- https://www.elifulkerson.com/projects/rawsniff.php    //Windows下流量镜像工具。W:netresec.com/?page=RawCap;--
- https://github.com/NytroRST/NetRipper    //支持截获像putty，winscp，mssql，chrome，firefox，outlook，https中的明文密码。
### 流量镜像重放
- https://github.com/didi/sharingan    //Go。流量录制，流量重放。
- https://github.com/shramos/polymorph    //支持几乎所有现有协议的实时网络数据包操作框架
- https://github.com/netsniff-ng/netsniff-ng    //C。a fast zero-copy analyzer Linux网络分析器。pcap捕获和重放工具，trafgen数据包生成压测。
### 流量协议解析
- https://www.netresec.com/?page=Networkminer    ////网络取证分析工具，对比GrassMarlin。通过嗅探或者分析PCAP文件可以侦测到操作系统，主机名和开放的网络端口主机，可解析http 2与TLS加密。P:网络取证与监控caploader 流量捕获;P:polarproxy tls加密流量代理;--
- http://www.colasoft.com.cn/download.php    //科来网络分析系统，ping/mac地址扫/数据包重放/数据包生成。
- https://github.com/wireshark/wireshark    //Lua。议解析流量分析还原，可通过Windows变量名“SSLKEYLOGFILE”的变量导出目标网站证书，进行密钥导入到Wireshark流量解析。
- https://github.com/zeek/zeek    //C++。bro的升级版，主要用于对链路上所有深层次的可疑行为流量进行安全监控，为网络流量分析提供了一个综合平台，特别侧重于语义安全监控。goodjob。
- https://github.com/brimsec/brim    //JS。大型pcap流量包分析工具，可转换为zeek专有格式，结合wireshark对流量进行分析。goodjob。WebGUI。
- https://github.com/aol/moloch    //大规模全流量捕获分析系统，capture/viewer/elasticsearch。GreatJob。
- https://github.com/cisco/mercury    //C++。基于AF_PACKET和TPACKETv3网络元数据捕获和分析，pmercury指纹识别。
- http://lcamtuf.coredump.cx/p0f3    //C。p0f升级版，被动流量指纹识别TCP/http
- https://github.com/0x4D31/fatt    //Py。利用tshark对流量进行解析
- https://github.com/netxfly/xsec-traffic    //Go。轻量级的恶意流量分析程序，包括传感器sensor和服务端server 2个组件。
- https://gitee.com/qielige/openQPA    //协议分析软件QPA的开源代码，特点是进程抓包、特征自动分析。
- https://github.com/adulau/ssldump    //C。SSLv3/TLS网络协议分析器