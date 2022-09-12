# 风险解决方案
1. https://tech.meituan.com/tags/安全.html    --美团技术团队wiki
- https://www.nist.gov/topics/cybersecurity    --美国国家标准与技术研究院。NVD漏洞库
- https://www.mitre.org/publications/all    --mitre安全机构。CVE漏洞库
- https://www.alibabacloud.com/blog    --阿里安全建设
- https://security.tencent.com/index.php/blog/msg/139    --腾讯安全建设。网络空间安全时代的红蓝对抗建设。
- https://security.tencent.com/opensource/detail/19    --腾讯开源的xSRC应急响应中心cms框架。
- https://github.com/baidu-security    --百度安全建设
- https://ai.google/research/pubs/?area=SecurityPrivacyandAbusePrevention    --谷歌安全解决方案
- https://aws.amazon.com/cn/blogs/security/    --亚马逊安全建设
- https://code.fb.com/category/security/    --Facebook安全建设
- http://www.freebuf.com/articles/ics-articles/178822.html    --浅析煤炭企业如何进行工控安全建设。
- https://www.sec-un.org/金融业企业安全建设之路/    --金融业企业安全建设之路。niejun
- https://blogs.cisco.com/tag/ios-security    --思科网络设备操作维护系统IOS（互联网操作系统Internetwork Operating System）
- https://shield.mitre.org/attack_mapping/    --ATT&CK主动防御图谱。引导-收集-遏制-检测-扰乱-促进-合法化-实验测试
- https://d3fend.mitre.org/    --基于ATT&CK框架的D3FEND防御矩阵
- https://github.com/Bypass007/Safety-Project-Collection    --甲方安全开源项目清单。welljob。
## 安全产品设计
- https://www.fireeye.com/cyber-map/threat-map.html    --FireEye公司“网络威胁地图”
- https://cybermap.kaspersky.com/    --卡巴斯基(Kaspersky)的“网络实时地图”
- http://www.digitalattackmap.com/    --Arbor networks的由全球270个ISPs匿名分享流量的“数字攻击地图”
- https://hubble.nexusguard.com    --Nexusguard Hubble攻击地图
- https://book.yunzhan365.com/dksd/oyru/mobile/index.html    --基于攻击链的网络威胁捕猎架构设计原型
- http://www.colasoft.com.cn/download/network-defense-map-2018.pdf    --科来网络攻击与防范图谱
- https://www.jianshu.com/p/852e0fbe2f4c    --安全产品厂商分类
### 产品设计文档
- https://www.freebuf.com/sectool/135032.html/    --构建一个高交互型的难以发现的蜜罐
- https://bloodzer0.github.io/ossa/    --OSSA，利用开源组件进行安全建设。主机、扫描器、端口、日志、防护设备。goodjob。
- https://paper.seebug.org/913/    --如何打造自己的PoC框架-Pocsuite3-框架篇。simple。
- https://github.com/lenve/javadoc    --Java企业级项目需求文档

# 应用安全Devsecops建设
- https://www.securitypaper.org/    --SDL建设文档。开发安全生命周期管理
- https://github.com/Hygieia/Hygieia    --JS。Capitalone银行开源的DevOps利器
- https://snyk.io/    --无服务器，环境漏洞检测。SDL建设。G:/snyk/snyk;--
- https://www.fooying.com/from_sdl_to_devsecops_security_in_dev/    --从SDL到DevSecOps：始终贯穿开发生命周期的安全
- https://mp.weixin.qq.com/s/STBzFf-NtfbDEA5s9RBdaw    --公众号：秦波 大型互联网应用安全SDL体系建设实践

## 安全开发建设
### Java安全开发
- https://github.com/FallibleInc/security-guide-for-developers    --安全开发规范，实用性开发人员安全须知。
- https://gitee.com/9199771/sec_coding/blob/master/sec_coding.md    --Java安全编码规范-1.0.1 by k4n5ha0
- https://git.code.tencent.com/Tencent_Open_Source    --腾讯工蜂 代码安全指南。G:/Tencent/secguide;--
- https://www.anquanke.com/post/id/200860    --JEP290防范Java反序列化漏洞，基于名单过滤。
### JavaScript安全开发
- https://github.com/JacksonBruce/AntiXssUF    --C#。跨站脚本攻击（XSS）过滤器，以白名单的过滤策略，支持多种过滤策略。
- "网页安全政策"（Content Security Policy，缩写 CSP）防御xss，可以通过网页meta标签和http头。开启httponly；更换chrome；
- https://github.com/leizongmin/js-xss    --根据白名单过滤 HTML(防止 XSS 攻击)
- https://github.com/cure53/DOMPurify    --基于 HTML、MathML 和 SVG对DOM标签进行过滤配置。
- https://github.com/microcosm-cc/bluemonday    --Go。HTML sanitizer XSS过滤
### Web安全开发
- https://www.bbsmax.com/A/1O5EvMgyd7/    --CORS（跨域资源共享）的防御机制
- https://search.freebuf.com/search/?search=    --OWASP Top 10 2017 10项最严重的 Web 应用程序安全风险
### 供应链安全
- https://github.com/visma-prodsec/confused    --go。依赖包漏洞检测
- https://github.com/XmirrorSecurity/OpenSCA-cli    --go。扫描项目的第三方组件依赖及漏洞信息。
### 错误诊断
- https://github.com/alibaba/arthas    --Java诊断工具

## 低代码平台
1. https://github.com/Tencent/tmagic-editor    --typescript。腾讯低代码平台
2. https://github.com/sparrow-js/sparrow    --Js。低代码平台
3. https://github.com/imcuttle/mometa    --TypeScript。弱代码元编程，代码可视编辑，辅助编码工具
- https://yaoapps.com/    --Go。通过JSON的无代码开发套件。G:/YaoApp/yao;--
- https://copilot.github.com    --GPT-3训练自动匹配代码结构，AI自动写代码。

## 安全运维建设
- https://github.com/aqzt/kjyw    --快捷运维，代号kjyw，项目基于shell、python，运维脚本工具库，收集各类运维常用工具脚本，实现快速安装、快速配置策略等。安全专题
- https://github.com/openspug/spug/    --JS,Py。轻量级无Agent的自动化运维平台，整合了主机管理、主机批量执行、主机在线终端、文件在线上传下载、应用发布部署、在线任务计划、配置中心、监控、报警等功能。
- https://github.com/ngbdf/redis-manager    --Java。Redis 一站式管理平台，支持集群的监控、安装、管理、告警以及基本的数据操作。
- https://zhuanlan.zhihu.com/p/43716885/    --使用knockd管理高危端口。
### 自动化运维
- https://github.com/n8n-io/n8n    --工作流自动化工具
- https://github.com/caprover/one-click-apps    --自动化部署、一键打包应用。
- https://github.com/Tencent/bk-job    --Java。蓝鲸作业平台（Job）脚本管理系统
- https://github.com/jumpserver/jumpserver    --Python3。开源堡垒机跳板机。
- https://github.com/zhaojh329/rtty    --C。web堡垒机，终端访问。
- https://github.com/prometheus/prometheus    --Go。Google BorgMon监控系统的开源版本，支持通过配置文件、文本文件、Zookeeper、Consul、DNS SRV Lookup等方式指定抓取目标。
- https://github.com/fabric/fabric    --Py。通过SSH远程shell批量执行命令。P:expect;P:PsExec;P:MSF session -C “命令”;--
- https://github.com/ayoisaiah/f2    --Go。批量重命名工具。
- https://www.gnu.org/software/parallel/    --Linux并行执行shell命令&软件技巧。awk;grep;--
- https://github.com/joerick/pyinstrument    --快速定位运行最慢的代码
### ACL策略权限
- https://github.com/canix1/ADACLScanner    --Powershell3。AD域的DACLs、SACLs报表生成。
- https://github.com/cahi1l1yn/aclAuditor/    --Py。网络设备ACL策略隐患审计，支持华为、华三、思科、锐捷等主流品牌的路由、交换、防火墙。
### 登录管控
- https://github.com/hashicorp/vault    --密钥保险箱、密码管理、keycenter。P:1Password
- https://github.com/pomerium/pomerium    --基于上下文身份动态访问策略的单点登录网关，VPN替代方案。
- https://github.com/dromara/sa-token    --Java。Java权限认证框架，主要解决：登录认证、权限认证、Session会话、单点登录、OAuth2.0 等一系列权限相关问题。
- https://github.com/cdk8s/tkey    --Java。Token Key 以 OAuth 2.0 标准为接口设计原则的单点登录系统（SSO）
- https://ln2.io/adminBoard    --Chrome 浏览器插件LN2 for Admin，蓝图局域网资产服务登录口管理。
- https://github.com/openitsystem/itops    --PY3,Django。AD\Exchange安全运维管理系统。
### API接口管理
- https://www.cnblogs.com/jurendage/p/12653865.html    --TecTeach。Java生鲜电商平台-API接口设计之token、timestamp、sign 具体架构与实现（APP/小程序，传输安全）。
- https://github.com/star7th/showdoc    --JS。开发文档、接口管理平台。
- https://github.com/ymfe/yapi    --JS。可本地部署的、打通前后端及QA的、可视化的接口管理平台。goodjob。
- https://github.com/mockoon/cli    --图形化api管理 数据mock工具，。
- https://github.com/eolinker/eoapi    --TS。图形化接口管理
- https://www.postman.com/    --API接口调试助手，一键生成demo代码，支持通过js插件进行测试。W:hookbin.com/;P:hackbar;P:CryptoJS;P:forgeJS;W:apifox.cn--
### Nginx配置
- https://github.com/bunkerity/bunkerized-nginx    --nginx安全镜像docker一键配置。
- https://github.com/trimstray/nginx-admins-handbook    --nginx操作手册。8k
- https://github.com/valentinxxx/nginxconfig.io/    --在线nginx配置文件生成，W:nginxconfig.io;--
### 负载均衡
- https://github.com/github/glb-director    --负载均衡组件GLB，数据解析使用了dpdk。
- https://mp.weixin.qq.com/s/QmCLYfQgR8vJXX1MFow3ow    --不到3000块钱，如何支撑起每月500万次访问量及80TB流量的网站？
### 系统运维
- https://www.itsk.com/index.php    --IT天空，系统操作运维。
- https://www.itsk.com/thread-401292-1-1.html    --it天空easysysprep以微软系统准备工具 sysprep.exe 程序为核心， Windows 操作系统封装部署辅助工具。
- https://www.chuyu.me/zh-Hans/index.html    --DISM++ Dism GUI，系统调试。Github:/Chuyu-Team/Dism-Multi-language;--
- https://www.sordum.org/    --Windows免费工具，防火墙操作、权限控制、网络诊断等
- https://github.com/RoliSoft/WSL-Distribution-Switcher    --Py3。Windows下Linux子系统WSL管理工具
- https://wpd.app/    --消除Windows隐私监控。P:DWS(Destroy-Windows-10-Spying);G:/crazy-max/WindowsSpyBlocker;--

## 办公网安全建设
- https://github.com/sgabe/SymlinkProtect    --Windows的文件系统微型过滤器驱动程序，用于阻止符号链接攻击。
- https://github.com/trimstray/iptables-essentials    --IP table常见防火墙规则与命令。P:/Firewall App Blocker 1.7 Windows防火墙快捷操作工具;P:/Linux下防火墙 firewall-cmd;--
- https://github.com/SELinuxProject/selinux/    --C。安全增强型Linux（Security-Enhanced Linux），通过配置增强主机防护安全防御。
- https://github.com/torvalds/linux/blob/master/drivers/net/macsec.c    --C。利用Linux macsec进行链路层流量安全加密。
### 内网流量安全
- https://github.com/shellster/DCSYNCMonitor    --域控制器检测 DCSync 攻击
### DNS防护建设
- https://github.com/mwrlabs/dref    --DNS 重绑定利用框架
- https://github.com/chengr28/Pcap_DNSProxy/blob/master/README.zh-Hans.md    --Pcap DNS Proxy 是一个基于 WinPcap/LibPcap 用于过滤 DNS 投毒污染的工具
### 邮件网关建设
- https://github.com/Janusec/janusec    --Golang。应用安全网关，具备WAF、CC攻击防御、证书私钥加密、负载均衡、统一Web化管理等功能。
- https://github.com/TKCERT/mail-security-tester    --检测邮件防护与过滤系统的测试框架
- https://www.freebuf.com/articles/web/227694.html/    --垃圾邮件防御手段，通过SPF记录；DKIM数据签名进行；DMARC策略（基于SPF和DKIM协议的可扩展电子邮件认证协议），关于钓鱼邮件的学习笔记。

## 云安全建设
- https://github.com/dafthack/CloudPentestCheatsheets/    --云原生渗透备忘单，云服务检查清单。
- https://github.com/riskscanner/riskscanner    --公有云安全合规扫描平台，通过 Cloud Custodian 的 YAML DSL 定义扫描规则
- https://github.com/mrknow001/aliyun-accesskey-Tools    --记一次阿里云主机泄露Access Key到Getshell
- https://github.com/tmobile/pacbot    --Java。云平台自动化安全监控工具。
- https://github.com/open-falcon    --GO,Py。Falco是一款由Sysdig开源的进程异常行为检测工具，能够检测传统主机上的应用程序，也能够检测容器环境和云平台（主要是Kubernetes和Mesos）。Github:/falcosecurity/falco;--
### 容器安全
- https://cloud.tencent.com/developer/article/1621185    --【云原生攻防研究】针对容器的渗透测试方法
- https://vulnerablecontainers.org    --对公开docker容器镜像漏洞扫描对标CVE号
- https://github.com/cdk-team/CDK/wiki/CDK-Home-CN    --容器环境逃逸、横向移动、持久化利用方式，插件化管理。
- https://github.com/brompwnie/botb    --Go。BOtB容器安全分析和脆弱点利用工具。利用CVE-2019-5736、DockerSocket或特权模式进行容器逃逸。
- https://github.com/knqyf263/trivy    --Go。针对容器的漏洞扫描器。G:/cr0hn/dockerscan;--
- https://github.com/P3GLEG/WhaleTail    --根据docker镜像生成dockerfile。
- https://github.com/chaitin/libveinmind    --问脉容器感知与安全 SDK
- https://github.com/chaitin/veinmind-tools    --基于veinmind-sdk打造的容器安全工具集
### Kubernetes集群安全
- https://forum.butian.net/share/1095    --云原生之Kubernetes安全
- https://github.com/kabachook/k8s-security/    --bash,Py。k8s安全配置。
- https://jimmysong.io/kubernetes-hardening-guidance/    --Kubernetes加固指南。G:/rootsongjc/kubernetes-hardening-guidance;--
- https://github.com/aquasecurity/kube-hunter    --Py。采用了KHV + 数字进行漏洞编号，云原生环境Kubernetes框架漏洞扫描工具。W:info.aquasec.com/kubernetes-security;--
- https://github.com/inguardians/peirates    --Go。Kubernetes集群的渗透测试工具，专注于权限提升和横向移动。
- https://github.com/skelsec/kerberoast/    --Py3。全自动获取DC服务器票据，Kubernetes渗透测试。G:/inguardians/peirates;P:kerberosGui;--
- https://github.com/aquasecurity/kube-bench    --Go。k8s安全基线测试工具。W:cisecurity.org/benchmark/kubernetes;--
- https://mp.weixin.qq.com/s/a7EtloE3guwfsRXD1m7IHg    --k8s sec 简易指南（攻击面及加固）
### 亚马逊AWS安全相关
- https://github.com/RhinoSecurityLabs/Cloud-Security-Research    --Py。AWS云安全研究工具集。G:/toniblyx/my-arsenal-of-aws-security-tools;
- https://github.com/RhinoSecurityLabs/pacu    --亚马逊AWS漏洞检测框架
- https://github.com/stuhirst/awssecurity/blob/master/arsenal.md    --AWS 安全检测相关的项目列表
- https://github.com/kromtech/s3-inspector    --检测亚马逊AWS S3 bucket permissions
- https://github.com/jordanpotti/AWSBucketDump    --枚举AWS S3 buckets以查找敏感机密的文件。G:/sa7mon/S3Scanner;--
- https://github.com/dowjones/hammer    --Py。AWS的多账户云安全工具，可识别不安全配置与资源中的敏感信息，良好的报告与修复功能。
- https://github.com/brandongalbraith/endgame    --aws测试工具，一键添加后门。
- https://github.com/Netflix/repokid    --AWS 最低权限策略部署工具

## 安全中心实验室建设
- https://www.freebuf.com/articles/es/211571.html    --安全实验室的发展及展望
- 公众号：开篇|猪八戒安全建设漫谈 安全体系建设分享01期|目标、团队、考核    --
- https://bbs.ichunqiu.com/thread-53927-1-1.html    --奇安信「实战攻防三部曲」要点总结。实战攻防之红蓝紫队
- https://github.com/Leezj9671/offensiveinterview    --安全/渗透测试/红队面试题。G:/WebBreacher/offensiveinterview;--
### 攻击模拟风险测试
- https://github.com/guardicore/monkey    --Py。利用默认口令、exp、多种协议（wmi组件、ssh、smb等）方式进行C2通讯、模拟病毒恶意传播等自动化渗透测试。G:/ElevenPaths/ATTPwn;G:/Manticore-Platform/manticore-cli/;W:guardicore.com/infectionmonkey;G:/lawrenceamer/0xsp-Mongoose;G:/NextronSystems/APTSimulator;G:/mitre/caldera;--
- https://github.com/alphasoc/flightsim    --Golang。Malicious恶意网路流量模拟测试。
- https://github.com/mitre-attack/attack-arsenal    --MITRE关于攻击团队模拟攻击仿真资源集合。
### 红队基础设施自动化部署建设
- https://github.com/QAX-A-Team/LuWu    --Bash。红队基础设施自动化部署工具
- 公众号：红队攻防全流程解析    --
- https://github.com/chryzsh/DarthSidious    --从0开始你的域渗透之旅。渗透测试域环境搭建。G:/crazywa1ker/DarthSidious-Chinese;--
### 安全测试系统
- https://www.parrotsec.org    --鹦鹉安全操作系统。pentest kali系统类。
- https://tails.boum.org/index.en.html    --tails匿名操作系统。pentest kali系统类。
- https://github.com/fireeye/commando-vm    --FireEye开源Commando VM，专为红队（pen-testing）定制的Windows。W:blackwin.ir --win-kali系统类;--
- https://github.com/moki-ics/moki    --工控渗透测试环境一键配置脚本
### Linux利用工具集合
- https://github.com/Z4nzu/hackingtool    --Linux安全工具集合，类pentestbox架构。
- https://github.com/Manisso/fsociety    --Linux下渗透工具包一键安装。G:/taielab/Taie-RedTeam-OS;--
- https://github.com/LionSec/katoolin    --Linux一键kali工具包。G:/thirdbyte/ssj;--
- https://github.com/TrustedSec/ptf/    --Py。基于Debian/Ubuntu/ArchLinux下的测试工具安装管理工具
- https://github.com/undefinedsec/VpsEnvInstall/    --测试环境一键配置脚本
### Windows利用工具集合
- http://www.nirsoft.net/    --实用工具软件远古大神Nir Sofer Windows工具集，密码恢复、系统管理、浏览器监控、系统调试、网络监控、Outlook调试。Goodjob。G:/BlackDiverX/cqtools;--
- https://github.com/RcoIl/CSharp-Tools    --安全测试CSharp工具集。编码转换、navicat密码抓取、weblogic反序列化、信息搜集、DES解密、机器类型判断、远程利用、C段标题WebTitle。
- https://github.com/k8gege/K8tools    --K8工具合集(内网渗透/提权工具/远程溢出/漏洞利用/扫描工具/密码破解/免杀工具/Exploit/APT/0day/Shellcode/Payload/priviledge/BypassUAC/OverFlow/WebShell/PenTest) Web GetShell Exploit(Struts2/Zimbra/Weblogic/Tomcat/Apache/Jboss/DotNetNuke/zabbix)。W:k8gege.org/;P:/cnblogs.com/k8gege --常见解压密码Kk8team\Kk8gege;G:/zzwlpx/k8fly --k8飞刀源码;--
- https://github.com/3gstudent/Homework-of-C-Sharp/    --C#。三好学生文章、工具、脚本。P:/3gstudent/Homework-of-Python;--
- https://github.com/Al1ex/Pentest-tools    --内网渗透工具
- https://github.com/microsoft/WindowsProtocolTestSuites    --C#。针对Windows开发规范的Windows协议测试套件。
### 安全测试辅助
- https://github.com/knownsec/404StarLink-Project    --知道创宇404星链。goodjob。Kunlun-Mirror 白盒代码审计；LBot Xss bot模板；Zoomeye Tools chrome插件；wam webapp、行业动态监控平台；bin_extractor 二进制敏感信息；CookieTest 测试api或某个请求的必选参数、cookie脚本；ipstatistics 基于ipip库的筛选ip列表脚本；cidrgen 基于cidr的子网IP列表生成器。
- https://github.com/LasCC/Hack-Tools    --渗透辅助
- http://requestbin.net/    --Inspect HTTP Requests。获取客户端http、dns请求。requestbin.com。
- https://github.com/BugScanTeam/DNSLog    --py。四叶草基于django监控 DNS 解析记录和 HTTP 访问记录的工具，将 DNSServer 集成进 DNSLog 中，检测多种类型的blind漏洞。G:/lijiejie/eyes.sh;G:/allyomalley/dnsobserver;G:/projectdiscovery/interactsh-web/;G:/Buzz2d0/Hyuga;--
- http://ceye.io    --知道创宇dns日志访问记录查询，可配合盲注、xss、解析对方真实ip使用。W:dnslog.cn/;W:app.interactsh.com;--
- https://github.com/opensec-cn/vtest    --Py。安全工程师渗透测试辅助，集合了mock、httplog、dns tools、xss，可用于测试各类无回显、无法直观判断或特定场景下的漏洞。
- https://github.com/phith0n/conote-community    --Py。短域名+dnslog
- https://github.com/ismailtasdelen/hackertarget    --Py。Use open source tools and network intelligence to help organizations with attack surface discovery and identification of security vulnerabilities。在线网络安全工具。
- https://github.com/uknowsec/SharpNetCheck    --C#。配合如wmiexec、psexec等横向工具进行批量检测内网是否出网。
- https://github.com/ultrasecurity/webkiller    --Py。ip信息、端口服务指纹、蜜罐探测、bypass cloudflare。
- https://github.com/medbenali/CyberScan    --Py。分析数据包、解码、端口扫描、IP地址分析等。
- https://github.com/alienwithin/OWASP-mth3l3m3nt-framework    --exp搜寻、payload与shell生成、信息收集
- https://github.com/feross/SpoofMAC    --Py。跨平台mac修改。P:TMAC v6;--
- https://github.com/foryujian/ipintervalmerge    --IP合并区间。
### 测试总结报告
- https://github.com/gh0stkey/PoCBox    --PHP。漏洞测试验证/报告生成平台。SONP劫持、CORS、Flash跨域资源读取、Google Hack语法生成、URL测试字典生成、JavaScript URL跳转、302 URL跳转
- https://github.com/pwndoc/pwndoc    --Vue.js。安全服务渗透测试报告生成。G:/bugsafe/WeReport;G:/blacklanternsecurity/writehat;P:HTMLTestRunner;--

## 基线核查List
- https://downloads.cisecurity.org/#/    --CIS-Benchmark基线手册 200+。greatjob。
- https://www.open-scap.org/    --安全基线评估工具集
- https://github.com/re4lity/Benchmarks    --常用服务器、数据库、中间件安全配置基线 ，基本包括了所有的操作系统、数据库、中间件、网络设备、浏览器、安卓、IOS、云服务的安全配置。
- https://github.com/aqzt/sso    --服务器安全运维规范（Server security operation）
- https://github.com/imthenachoman/How-To-Secure-A-Linux-Server    --Linux服务器保护。
- https://github.com/Jsitech/JShielder    --Linux下服务器一键加固脚本
- https://github.com/trimstray/linux-hardening-checklist    --Linux服务器加固基线
- https://github.com/a13xp0p0v/kconfig-hardened-check    --用于检查 Linux 内核配置中的安全加固选项的脚本
- https://madaidans-insecurities.github.io/guides/linux-hardening.html    --Linux安全加固条例。
- https://gist.github.com/mackwage/08604751462126599d7e52f233490efe    --Windows安全加固命令。
- https://github.com/drduh/macOS-Security-and-Privacy-Guide    --Py。MacOS安全性基线。
- https://github.com/wstart/DB_BaseLine    --数据库检查基线工具。
### 安全测试CheckList
- https://github.com/juliocesarfort/public-pentesting-reports    --由几家咨询公司和学术安全组织发布的公共渗透测试报告的列表。
- http://pentestmonkey.net/category/cheat-sheet    --渗透测试常见条目
- https://github.com/0xRadi/OWASP-Web-Checklist    --owasp网站检查条目
- https://blog.csdn.net/qq_39541626/article/details/104891590    --TecTeach。小程序、公众号安全测试list。
- https://www.jianshu.com/p/8253adac33d8    --渗透测试 Node.js 应用
- https://xz.aliyun.com/t/2089    --金融科技SDL安全设计checklist。
- https://github.com/tonghuaroot/Awesome-macOS-Red-Teaming    --macos测试条例
### 安全测试速查表
- https://github.com/HarmJ0y/CheatSheets    --多个工具速查手册（Beacon / Cobalt Strike，PowerView，PowerUp，Empire和PowerSploit）G:/louchaooo/kali-tools-zh;G:/b1n4ry4rms/RedTeam-Pentest-Cheatsheets/;--
- https://mp.weixin.qq.com/s/y3IdYSIDckQTaPgNQMS7Cg    --公众号：常见端口渗透笔录
- https://tool.oschina.net/commons/    --常用对照表。http文件类型、转码、转义、端口、状态码、字体。
- https://book.hacktricks.xyz/    --端口漏洞对应，渗透命令，提权技巧。goodjob。W:ired.team;
- https://github.com/swisskyrepo/PayloadsAllTheThings    --Web渗透/CTF/XXE/常用脚本命令payloads。8K,goodjob。
- https://www.octority.com/pepenote/    --10w行渗透测试命令

## IPv6安全建设
- https://github.com/sfan5/fi6s    --ipv6端口快速扫描器
- https://github.com/fgont/ipv6toolkit    --C。si6networks.com组织的ipv6工具集
- https://github.com/lavalamp-/ipv666    --Go。ipv6地址枚举扫描
## 人工智能安全
- https://github.com/Azure/counterfit/    --python。自动化测试人工智能AI模型
## 零信任建设
- https://zhuanlan.zhihu.com/p/101989442    --5分钟了解谷歌BeyondCorp零信任安全模型。P:Airbnb的零信任架构实战案例;--

## 合规建设
- https://mp.weixin.qq.com/s/uD8xZse3TLH7vjzJOp_kxw    --网信办、工信部教我做产品！W:note.youdao.com/s/K4vFx4Ki --网信办、工信部学习资料（欢迎收藏备用）
### 合规安全
1. https://github.com/bytedance/appshark    --Kotlin。字节移动端合规安全检测
- https://github.com/momosecurity/bombus    --Vue,Py。依据为SOX法案陌陌开源的安全合规审计平台
- https://mp.weixin.qq.com/s/IoVzbLSxPI3m3v47X8jB_A    --App合规实践3000问
### 等保安全
- https://mp.weixin.qq.com/s/gcohsAQSHHCVoG-HlYYaeg    --公众号：等级保护测评方法（精华版）
- https://github.com/paradiseduo/ApplicationScanner    --Python。移动端App等保测试工具。
### 数据安全
- https://github.com/mydlp    --MyDLP是一种简单，简单和开放的DLP（数据丢失预防）解决方案
- https://github.com/bytedance/godlp    --字节数据DLP
### 数字水印
- https://github.com/CN-Chrome-DevTools/CN-Chrome-DevTools    --Chrome开发者工具中文手册
- https://github.com/saucxs/watermark-dom    --基于DOM对象实现的BS系统的水印
- https://github.com/fire-keeper/BlindWatermark    --py。数字水印盲水印图片保护。
- https://github.com/rohitrango/automatic-watermark-detection/    --Py。自动检测去水印。
- https://github.com/thinkst/canarytokens    --Py。重要文件的追踪溯源，信标定位（canarytokens.org/generate#）服务端代码/蜜标。

## 安全风控建设
1. https://github.com/skyhackvip/risk_engine    --GOLANG。风控决策引擎系统。
- https://github.com/threathunterX/nebula    --LUA,Perl。威胁猎人开源"星云"业务风控系统
- https://github.com/momosecurity/aswan    --Py。陌陌风控系统静态规则引擎，零基础简易便捷的配置多种复杂规则，实时高效管控用户异常行为。
- https://github.com/xdite/internet-security    --互联网金融企业安全与风控的实战手册。资安风控。
- https://help.aliyun.com/document_detail/73845.html    --相同的card_id在十分钟内，在两个不同的location发生刷卡现象，就会触发报警机制，以便监测信用卡盗刷等现象。
- https://mp.weixin.qq.com/s/KcTbNv88swlFIYIA1pFkLw    --每日优鲜非战斗亏损风控

## 安全运营建设
- 公众号：终端安全运营年度笔记    --
- http://paper.tuisec.win/detail/34ab12018f71e71    --个人总结的漏洞管理流程分享
- 公众号：评估一个新的安全数据源的有效性: Windows Defender 漏洞利用防护（上、下）
- https://www.alienvault.com/products/ossim    --开源信息安全管理系统siem平台解决方案，支持snort\nmap等多种工具插件。
- https://thehive-project.org/    --安全事件响应平台。G:/TheHive-Project/TheHive;--
### SOC建设
- https://www.secrss.com/articles/8051    --谈一谈如何建设体系化的安全运营中心(SOC)
- http://www.freebuf.com/articles/network/169632.html    --开源软件创建SOC的一份清单
- https://www.secrss.com/articles/4088    --安全资产管理中容易被忽视的几点。niejun
- https://github.com/correlatedsecurity/Awesome-SOAR    --安全编排、自动化及响应
- https://gitee.com/zbnio/zbn    --Py。soar布谷鸟安全编排与自动化响应平台。G:/w5teams/w5;--