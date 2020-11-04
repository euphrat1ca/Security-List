***项目简介***
根据中华人民共和国《网络安全法》相关政策规定，本文章只做学习测试，不被允许通过本文章技术手段进行非法行为，使用技术的风险由您自行承担(The author does not assume any legal responsibility)<br>
&emsp;&emsp;https://github.com/euphrat1ca/security_w1k1 //Have to say,the index is in my mind<br>
&emsp;&emsp;一个 Red Team 攻击的生命周期，整个生命周期包括：信息收集、攻击尝试获得权限、持久性控制、权限提升、网络信息收集、横向移动、数据分析（在这个基础上再做持久化控制）、在所有攻击结束之后清理并退出战场（扫尾）。<br>
&emsp;&emsp;几千行的项目有点过于庞大，于是在第两百次更新的时候，选择把一些较为频繁的持续更新内容分到其它文件内。<br>
分类标签：mywiki;教程TechTeach;介绍intro;使用手册;通讯技术;威胁情报;恶意样本;自服务应用;研究技术;漏洞利用;Web安全;移动安全;数字取证;权限拓展;模糊测试;极客学习;万物互联;情报研判;工具插件;安全防护;etc…<br>
导航标签：一个人的安全部;Awesome系列;类似于xx架构;etc…<br>
类型标签：模拟测试;Kali系统类;ATT&CK矩阵类;作者拼音;Github:\Web:\Page:\Connect 等常见缩写;etc…<br>
状态标签：Simple;NoUpdate;商业版;社区版;<br>
测评标签：testjob（待测试）;welljob（还可以）;goodjob（很不错）;greatjob（行业标杆）;<br>
## 安全建设方案
- https://www.nist.gov/topics/cybersecurity    //美国国家标准与技术研究院。NVD漏洞库
- https://www.mitre.org/publications/all    //mitre安全机构。CVE漏洞库
- https://www.alibabacloud.com/blog    //阿里安全建设
- https://security.tencent.com/index.php/blog/msg/139    //腾讯安全建设。网络空间安全时代的红蓝对抗建设。
- https://security.tencent.com/opensource/detail/19    //腾讯开源的xSRC应急响应中心cms框架。
- https://github.com/baidu-security    //百度安全建设
- https://ai.google/research/pubs/?area=SecurityPrivacyandAbusePrevention    //谷歌安全建设
- https://aws.amazon.com/cn/blogs/security/    //亚马逊安全建设
- https://code.fb.com/category/security/    //Facebook安全建设
- http://www.freebuf.com/articles/ics-articles/178822.html    //浅析煤炭企业如何进行工控安全建设
- https://www.sec-un.org/金融业企业安全建设之路/    //金融业企业安全建设之路。niejun
- https://blogs.cisco.com/tag/ios-security    //思科网络设备操作维护系统IOS（互联网操作系统Internetwork Operating System）
### 安全建设防御方案
- https://github.com/JacksonBruce/AntiXssUF    //C#。跨站脚本攻击（XSS）过滤器，以白名单的过滤策略，支持多种过滤策略。
- "网页安全政策"（Content Security Policy，缩写 CSP）防御xss，可以通过网页meta标签和http头。开启httponly；更换chrome；
- https://www.bbsmax.com/A/1O5EvMgyd7/    //CORS（跨域资源共享）的防御机制
- https://www.freebuf.com/articles/web/227694.html/    //垃圾邮件防御手段，通过SPF记录；DKIM数据签名进行；DMARC策略（基于SPF和DKIM协议的可扩展电子邮件认证协议）。关于钓鱼邮件的学习笔记
- https://zhuanlan.zhihu.com/p/43716885/    //使用knockd管理高危端口
### 红队基础设施自动化部署建设
- https://github.com/QAX-A-Team/LuWu    //Bash。红队基础设施自动化部署工具
- 公众号：红队攻防全流程解析    //
- https://github.com/chryzsh/DarthSidious    //从0开始你的域渗透之旅。渗透测试域环境搭建。G:/crazywa1ker/DarthSidious-Chinese;--
### 安全实验室中心建设
- https://www.freebuf.com/articles/es/211571.html    //安全实验室的发展及展望
- 公众号：开篇|猪八戒安全建设漫谈 安全体系建设分享01期|目标、团队、考核    //
- https://bbs.ichunqiu.com/thread-53927-1-1.html    //奇安信「实战攻防三部曲」要点总结。实战攻防之红蓝紫队
- https://github.com/Leezj9671/offensiveinterview    //安全/渗透测试/红队面试题.G:/WebBreacher/offensiveinterview;
### 安全运营中心(SOC)建设
- https://www.secrss.com/articles/8051    //谈一谈如何建设体系化的安全运营中心(SOC)
- http://www.freebuf.com/articles/network/169632.html    //开源软件创建SOC的一份清单
- http://paper.tuisec.win/detail/34ab12018f71e71    //个人总结的漏洞管理流程分享
- https://www.secrss.com/articles/4088    //安全资产管理中容易被忽视的几点。niejun
- 公众号：评估一个新的安全数据源的有效性: Windows Defender 漏洞利用防护（上、下）
- 公众号：终端安全运营年度笔记    //
- https://github.com/correlatedsecurity/Awesome-SOAR    //安全编排、自动化及响应
### 安全风控建设
- https://github.com/threathunterX/nebula    //LUA/Perl。威胁猎人开源"星云"业务风控系统
- https://github.com/momosecurity/aswan    //Py。陌陌风控系统静态规则引擎，零基础简易便捷的配置多种复杂规则，实时高效管控用户异常行为。
- https://github.com/xdite/internet-security    //互联网金融企业安全与风控的实战手册。资安风控
### 安全开发
- https://github.com/FallibleInc/security-guide-for-developers    //安全开发规范
- https://www.securitypaper.org/    //SDL建设文档。开发安全生命周期管理
- https://github.com/Hygieia/Hygieia    //JS。Capitalone银行开源的DevOps利器
- https://snyk.io/    //无服务器，环境漏洞检测。SDL建设。G:/snyk/snyk;
- https://mp.weixin.qq.com/s/STBzFf-NtfbDEA5s9RBdaw/    //公众号：秦波 大型互联网应用安全SDL体系建设实践
### 产品设计原型
- https://www.fireeye.com/cyber-map/threat-map.html    //FireEye公司“网络威胁地图”
- https://cybermap.kaspersky.com/    //卡巴斯基(Kaspersky)的“网络实时地图”
- http://www.digitalattackmap.com/    //Arbor networks的由全球270个ISPs匿名分享流量的“数字攻击地图”
- https://hubble.nexusguard.com    //Nexusguard Hubble攻击地图
- https://echarts.baidu.com/examples/index.html#chart-type-globe    //Echart图
- https://book.yunzhan365.com/dksd/oyru/mobile/index.html    //基于攻击链的网络威胁捕猎架构设计
- http://www.colasoft.com.cn/download/network-defense-map-2018.pdf    //科来网络攻击与防范图谱
- https://www.anquanke.com/post/id/178339    //漏扫动态爬虫实践。pyppeteer
- https://www.jianshu.com/p/852e0fbe2f4c    //安全产品厂商分类
- https://github.com/xianlimei/yiwei.github.io/wiki    //私有云、区块链安全研究，rasp、waf、主机安全产品介绍
### 产品设计文档
- https://www.freebuf.com/sectool/135032.html/    //构建一个高交互型的难以发现的蜜罐
- https://bloodzer0.github.io/ossa/    //OSSA，利用开源组件进行架构.主机、扫描器、端口、日志、防护设备等安全建设。goodjob。
- https://github.com/dvf/blockchain    //用Python从零开始创建区块链
- https://paper.seebug.org/913/    //如何打造自己的PoC框架-Pocsuite3-框架篇。simple。
## 安全运维
- https://github.com/aqzt/kjyw    //快捷运维，代号kjyw，项目基于shell、python，运维脚本工具库，收集各类运维常用工具脚本，实现快速安装、快速配置策略等。安全专题
- https://github.com/openspug/spug/    //JS,Py。轻量级无Agent的自动化运维平台，整合了主机管理、主机批量执行、主机在线终端、文件在线上传下载、应用发布部署、在线任务计划、配置中心、监控、报警等功能。
### 等保安全
- https://mp.weixin.qq.com/s/gcohsAQSHHCVoG-HlYYaeg    //公众号：等级保护测评方法（精华版）
### 系统ACL策略安全
- https://www.4hou.com/penetration/5752.html    //Intro。域渗透提权分析工具 BloodHound 1.3 中的ACL攻击路线。
- https://github.com/canix1/ADACLScanner    //Powershell3。AD域的DACLs、SACLs报表生成。
- https://github.com/cahi1l1yn/aclAuditor/    //Py。网络设备ACL策略隐患审计，支持华为、华三、思科、锐捷等主流品牌的路由、交换、防火墙。
### 运维手册
- https://www.cisecurity.org/cis-benchmarks/    //CIS总结的140多种配置基准
- https://github.com/aqzt/sso    //服务器安全运维规范（Server security operation）
- https://github.com/imthenachoman/How-To-Secure-A-Linux-Server    //Linux服务器保护。9k
#### Nginx配置
- https://github.com/bunkerity/bunkerized-nginx    //nginx安全镜像docker一键配置。
- https://github.com/trimstray/nginx-admins-handbook    //nginx操作手册。8k
- https://github.com/valentinxxx/nginxconfig.io/    //在线nginx配置文件生成，W:nginxconfig.io;--
### 系统安全基线检查
- https://www.open-scap.org/    //安全基线评估工具集
- https://github.com/re4lity/Benchmarks    //常用服务器、数据库、中间件安全配置基线 ，基本包括了所有的操作系统、数据库、中间件、网络设备、浏览器、安卓、IOS、云服务的安全配置。
- https://github.com/Jsitech/JShielder    //linux下服务器一键加固脚本
- https://github.com/trimstray/linux-hardening-checklist    //Linux服务器加固基线
- https://github.com/a13xp0p0v/kconfig-hardened-check    //用于检查 Linux 内核配置中的安全加固选项的脚本
- https://gist.github.com/mackwage/08604751462126599d7e52f233490efe    //Windows安全加固命令
- https://github.com/wstart/DB_BaseLine    //数据库检查基线工具
- https://github.com/drduh/macOS-Security-and-Privacy-Guide    //Py。MacOS安全性基线。
### 安全测试checklist
- https://github.com/juliocesarfort/public-pentesting-reports    //由几家咨询公司和学术安全组织发布的公共渗透测试报告的列表。
- http://pentestmonkey.net/category/cheat-sheet    //渗透测试常见条目
- https://github.com/0xRadi/OWASP-Web-Checklist    //owasp网站检查条目
- https://mp.weixin.qq.com/s/O36e0gl4cs0ErQPsb5L68Q    //公众号：区块链、以太坊智能合约审计 CheckList
- https://github.com/slowmist/eos-bp-nodes-security-checklist    //区块链，EOS bp nodes security checklist（EOS超级节点安全执行指南）
- https://www.cnblogs.com/jurendage/p/12653865.html    //TecTeach。Java生鲜电商平台-API接口设计之token、timestamp、sign 具体架构与实现（APP/小程序，传输安全）
- https://blog.csdn.net/qq_39541626/article/details/104891590    //TecTeach。小程序、公众号安全测试list
- https://github.com/shieldfy/API-Security-Checklist    //api开发核对清单。12k。
- https://github.com/GitGuardian/APISecurityBestPractices    //api接口测试checklist
- https://xz.aliyun.com/t/2089    //金融科技SDL安全设计checklist
- https://www.butian.net/School/content?id=307/    //移动通信网络渗透测试科普
### 安全知识库
- https://book.hacktricks.xyz/    //端口漏洞对应，渗透命令，提权技巧。goodjob。W:ired.team;G:/EvilAnne/Violation_Pnetest;--
- https://github.com/swisskyrepo/PayloadsAllTheThings    //Web渗透测试/CTF/XXE/常用脚本命令payloadsw。8K,goodjob。
- https://www.octority.com/pepenote/    //10w行渗透测试技巧
### 安全测试速查表
- https://github.com/HarmJ0y/CheatSheets    //多个工具速查手册（Beacon / Cobalt Strike，PowerView，PowerUp，Empire和PowerSploit）G:/louchaooo/kali-tools-zh;G:/b1n4ry4rms/RedTeam-Pentest-Cheatsheets/;--
- https://mp.weixin.qq.com/s/y3IdYSIDckQTaPgNQMS7Cg    //公众号：常见端口渗透笔录
- http://tool.oschina.net/commons/    //常用对照表，HTTP Content-type、TCP/UDP常见端口参考、字体、颜色等。
- https://tool.oschina.net/commons/    //常用对照表。http文件类型、转码、转义、端口、状态码、字体。
## IPv6安全
- https://github.com/sfan5/fi6s    //ipv6端口快速扫描器
- https://github.com/fgont/ipv6toolkit    //C。si6networks.com组织的ipv6工具集
- https://github.com/lavalamp-/ipv666    //Go。ipv6地址枚举扫描
- https://github.com/christophetd/IPv6teal    //Py。利用ipv6隐蔽隧道传输数据
## 合规审计
- https://github.com/momosecurity/bombus    //Vue,Py。依据为SOX法案陌陌开源的安全合规审计平台
## 区块安全
- https://github.com/quoscient/octopus    //区块链智能合约安全分析工具
- https://github.com/ConsenSys/mythril-classic    //以太坊智能协议区块链安全分析工具
## 云安全相关
- https://cloud.tencent.com/developer/article/1621185    //【云原生攻防研究】针对容器的渗透测试方法
- https://github.com/dafthack/CloudPentestCheatsheets/    //云渗透备忘单，云服务检查清单
- https://github.com/brompwnie/botb    //Go。BOtB容器安全分析和脆弱点利用工具。利用CVE-2019-5736、DockerSocket或特权模式进行容器逃逸。
### 容器安全
- https://vulnerablecontainers.org    //对公开docker容器镜像漏洞扫描，并标出CVE号
- https://github.com/P3GLEG/WhaleTail    //根据docker镜像生成成dockerfile
- https://github.com/cr0hn/dockerscan    //docker扫描工具
- https://github.com/knqyf263/trivy    //Go。针对容器的漏洞扫描器。2K。
### Kubernetes集群安全
- https://github.com/aquasecurity/kube-hunter    //Py。采用了KHV + 数字进行漏洞编号，云原生环境Kubernetes框架漏洞扫描工具。W:info.aquasec.com/kubernetes-security;--
- https://github.com/inguardians/peirates    //Go。Kubernetes集群的渗透测试工具，专注于权限提升和横向移动。
- https://github.com/kabachook/k8s-security/    //bash,Py。Kubernetes安全集合。
- https://github.com/aquasecurity/kube-bench    //Go。Kubernete安全检测工具，符合‘cisecurity.org/benchmark/kubernetes/’基准测试。
### 亚马逊AWS安全相关
- https://github.com/RhinoSecurityLabs/Cloud-Security-Research    //Py。AWS云安全研究，工具集。
- https://github.com/RhinoSecurityLabs/pacu    //亚马逊AWS漏洞检测框架
- https://github.com/stuhirst/awssecurity/blob/master/arsenal.md    //AWS 安全检测相关的项目列表
- https://github.com/toniblyx/my-arsenal-of-aws-security-tools    //AWS安全工具集
- https://github.com/sa7mon/S3Scanner    //扫描amazon公开的S3 buckets和dump
- https://github.com/kromtech/s3-inspector    //检测亚马逊AWS S3 bucket permissions
- https://github.com/jordanpotti/AWSBucketDump    //枚举AWS S3 buckets以查找敏感机密的文件
- https://github.com/Netflix/repokid    //AWS 最低权限策略部署工具
- https://github.com/dowjones/hammer    //Py。AWS的多账户云安全工具，可识别不安全配置与资源中的敏感信息，良好的报告与修复功能。
# 技术利用套件集合
- https://github.com/infosecn1nja/Red-Teaming-Toolkit    //红队攻击生命周期，开源和商业工具。goodjob。
- https://github.com/redcanaryco/atomic-red-team    //Atomic Red Team团队关于win、linux、mac等多方面apt利用手段、技术与工具集。2k。
- https://github.com/blaCCkHatHacEEkr/PENTESTING-BIBLE    //红队工具、攻击手段
- https://github.com/toolswatch/blackhat-arsenal-tools    //blackhat工具集
- https://github.com/demonsec666/Security-Toolkit    //渗透攻击链中常用工具及使用场景
- https://github.com/n00py/ReadingList/blob/master/gunsafe.txt    //安全工具集
- https://github.com/Z4nzu/hackingtool    //Linux安全工具集合，类似于pentestbox架构
- https://github.com/knownsec/404StarLink-Project    //知道创宇404星链。goodjob。Kunlun-Mirror 白盒代码审计；LBot Xss bot模板；ksubdomain 无状态子域名爆破；Zoomeye Tools chrome插件；wam webapp、行业动态监控平台；bin_extractor 二进制敏感信息；CookieTest 测试api或某个请求的必选参数、cookie脚本；ipstatistics 基于ipip库的筛选ip列表脚本；cidrgen 基于cidr的子网IP列表生成器；--
## 安全测试系统集合
- https://www.parrotsec.org    //鹦鹉安全操作系统。pentest kali系统类。
- https://tails.boum.org/index.en.html    //tails匿名操作系统。pentest kali系统类。
- https://github.com/fireeye/commando-vm    //FireEye开源Commando VM，专为红队（pen-testing）定制的Windows。W:blackwin.ir //win-kali系统类;--
- https://github.com/undefinedsec/VpsEnvInstall/    //测试环境一键配置脚本
- https://github.com/moki-ics/moki    //工控渗透测试环境一键配置脚本
- https://github.com/Manisso/fsociety    //Linux下渗透工具包一键安装。G:/taielab/Taie-RedTeam-OS;--
- https://github.com/LionSec/katoolin    //Linux服务器自动安装kali工具包
- https://github.com/TrustedSec/ptf/    //Py。基于Debian/Ubuntu/ArchLinux下的测试工具安装管理工具
## Windows利用工具集合
- https://github.com/BlackDiverX/cqtools    //Windows利用工具集
- https://github.com/RcoIl/CSharp-Tools    //安全测试CSharp - 工具集。编码转换、navicat密码抓取、weblogic反序列化、信息搜集、DES解密、机器类型判断、远程利用、C段标题WebTitle。
- https://github.com/microsoft/WindowsProtocolTestSuites    //C#。针对Windows开发规范的Windows协议测试套件。
- https://github.com/k8gege/    //K8工具合集(内网渗透/提权工具/远程溢出/漏洞利用/扫描工具/密码破解/免杀工具/Exploit/APT/0day/Shellcode/Payload/priviledge/BypassUAC/OverFlow/WebShell/PenTest) Web GetShell Exploit(Struts2/Zimbra/Weblogic/Tomcat/Apache/Jboss/DotNetNuke/zabbix)。P:/cnblogs.com/k8gege //常见解压密码Kk8team\Kk8gege;G:/zzwlpx/k8fly //k8飞刀源码;--
- https://github.com/3gstudent/Homework-of-C-Sharp/    //C#。三好学生文章工具、脚本。
- https://github.com/Al1ex/Pentest-tools    //内网渗透工具
## 安全测试辅助
- https://github.com/LasCC/Hack-Tools    //渗透测试辅助套
- http://requestbin.net/    //Inspect HTTP Requests。获取客户端http、dns请求。requestbin.com。
- https://github.com/BugScanTeam/DNSLog    //py。四叶草基于django监控 DNS 解析记录和 HTTP 访问记录的工具，将 DNSServer 集成进 DNSLog 中。
- https://github.com/opensec-cn/vtest    //Py。用于辅助安全工程师漏洞挖掘、测试、复现，集合了mock、httplog、dns tools、xss，可用于测试各类无回显、无法直观判断或特定场景下的漏洞。
- http://ceye.io    //知道创宇dns日志访问记录查询，可配合盲注、xss、解析对方真实ip使用。W:dnslog.cn/;--
- https://github.com/ismailtasdelen/hackertarget    //Py。Use open source tools and network intelligence to help organizations with attack surface discovery and identification of security vulnerabilities。
- https://github.com/ultrasecurity/webkiller    //Py。ip信息、端口服务指纹、蜜罐探测、bypass cloudflare。
- https://github.com/medbenali/CyberScan    //Py。分析数据包、解码、端口扫描、IP地址分析等。
- https://github.com/alienwithin/OWASP-mth3l3m3nt-framework    //exp搜寻、payload与shell生成、信息收集
- https://github.com/feross/SpoofMAC    //Py。跨平台mac修改。P:TMAC v6;--
- https://github.com/foryujian/ipintervalmerge    //IP合并区间。
### 测试报告
- https://github.com/gh0stkey/PoCBox    //PHP。漏洞测试验证/报告生成平台。SONP劫持、CORS、Flash跨域资源读取、Google Hack语法生成、URL测试字典生成、JavaScript URL跳转、302 URL跳转
- https://github.com/pwndoc/pwndoc    //Vue.js。安全服务渗透测试报告生成。
- https://github.com/bugsafe/WeReport    //PHP。WeReport报告助手，一键生成测试报告。
## 信息隐匿保护
- https://github.com/ffffffff0x/Digital-Privacy/    //一个关于数字隐私搜集、保护、清理集一体的方案,外加开源信息收集(OSINT)对抗。类似于 wiki_OsintData；wiki_SelfServicerce；wiki_FreeConnect。goodjob。
- https://github.com/leitbogioro/Fuck_Aliyun    //关闭阿里云监控服务
- https://www.anquanke.com/post/id/195011    //暗度陈仓：基于国内某云的 Domain Fronting 技术实践。CDN域前置。
- https://www.freebuf.com/sectool/232555.html    //利用Cloudflare Worker来隐藏C2基础设施。CDN域前置。G:/Berkeley-Reject/workers-proxy;--
- https://www.anquanke.com/post/id/220868    //TechTeach。利用heroku（容器云平台）隐藏C2服务器
### 隐匿流量洋葱路由
- https://www.torproject.org/    //洋葱浏览器。P:/dnmugu4755642434.onion/ kilos搜索引擎;--
- https://github.com/globaleaks/Tor2web    //darkweb暗网代理服务器，将onion的服务变为普通的服务
- https://github.com/milesrichardson/docker-onion-nmap    //使用nmap扫描Tor网络上隐藏的"onion"服务
- https://github.com/GouveaHeitor/nipe    //一个使所有流量通过Tor网络发出的脚本
- https://github.com/Edu4rdSHL/tor-router    //Bash。使用tor代理全部流量。dnsleaktest.com dns检测。
- https://github.com/trimstray/multitor    //Bash。启用多个TorBrowser通道转发流量，并设置负载均衡
- https://github.com/NullArray/NetSet    //Bash。终端多路复用器，其会话通过Tor路由，并通过自动安装和配置DNSCrypt-proxy来保护DNS流量。
## 社会工程
- https://github.com/mehulj94/Radium-Keylogger    //py。键盘记录工具。
- https://www.snapfiles.com/get/antikeyloggertester.html    //Windows客户端键盘记录工具AKLT。
- https://github.com/ggerganov/kbd-audio    //C++。linux下利用麦克风监控键盘输入测试输入值。
- https://github.com/Pickfordmatt/SharpLocker/    //c#。Windows锁屏密码记录。G:/bitsadmin/fakelogonscreen;PS:Invoke-LoginPrompt.ps1;PS:Invoke-CredentialsPhish.ps1;Koadic:password_box;Empire:collection/toasted;Empire:collection/prompt;MSF:phishwindowscredentials;--
- https://github.com/azizaltuntas/Camelishing    //Py3。社会工程学攻击辅助工具。WEBGUI。
- https://github.com/threatexpress/domainhunter    //检查过期域名，bluecoat分类和‘Archive.org’历史记录，以确定最为适合于钓鱼和C2的域名。
- https://github.com/Mr-Un1k0d3r/CatMyPhish    //收集目标类似于的尚未注册的域名。
- https://github.com/thinkst/canarytokens    //Py。重要文件的追踪溯源，信标定位（canarytokens.org/generate#）服务端代码。蜜标。
- https://github.com/Viralmaniar/I-See-You    //Bash。利用网站代理获取用户的真实地理信息。simple
- https://www.jianshu.com/p/147cf5414851    //聊聊那些常见的探侦类APP
### 网站克隆
- http://www.httrack.com    //网站克隆镜像
- https://github.com/JonCooperWorks/judas    //Go。克隆网站钓鱼
### 钓鱼框架
- https://github.com/bhdresh/SocialEngineeringPayloads    //负责收集用于证书盗窃和鱼叉式网络钓鱼攻击的社交工程技巧和payloads
- https://github.com/trustedsec/social-engineer-toolkit    //Py。TrustedSec开发的专为社交工程设计的开源渗透测试框架，SET框架支持网站克隆、邮件伪造、反弹shell等。G:/Raikia/FiercePhish;/securestate/king-phisher;G:/tatanus/SPF;G:/fireeye/ReelPhish;G:/samyoyo/weeman;G:/MSG-maniac/mail_fishing;--
- https://github.com/fireeye/PwnAuth    //OAuth欺骗、凭证钓鱼、绵阳墙。G:/AlteredSecurity/365-Stealer;--
- https://github.com/ustayready/CredSniper    //使用Flask和Jinja2模板编写的网络钓鱼框架，支持捕获2FA令牌。G:/kgretzky/evilginx2/;G:/drk1wi/Modlishka;--
- https://github.com/thelinuxchoice/blackeye    //Py。拥有facebook、instagram等三十余个钓鱼模板的一键启用工具。
- https://github.com/M4cs/BlackEye-Python    //Py。基于blackeye增加子域名模拟伪造功能。
- https://github.com/gophish/gophish    //Go。拥有在线模板设计、发送诱骗广告等功能的钓鱼系统。G:/L4bF0x/PhishingPretexts;--
- https://github.com/euphrat1ca/SpoofWeb    //PHP。通过nginx反代一键部署office365、outlook、coremail、深信服等https钓鱼网站模板。
- https://github.com/thelinuxchoice/lockphish    //shell,PHP。基于ngrok利用钓鱼网站获取锁屏密码（手机、电脑）。
- https://github.com/r00tSe7en/Flash-Pop    //flash更新弹窗伪造。goodjob。
### 邮件伪造
- https://github.com/n0pe-sled/Postfix-Server-Setup    //自动化建立一个网络钓鱼服务器，Postfix/Sendmail邮件系统。
- https://emkei.cz    //在线邮件伪造。多功能模拟。W:tool.chacuo.net/mailanonymous;--
W:ns4gov.000webhostapp.com;W:smtp2go.com/;--
- https://github.com/Macr0phag3/email_hack    //Py。钓鱼邮件伪造。G:/lunarca/SimpleEmailSpoofer;G:/Dionach/PhEmail;--
- https://www.jetmore.org/john/code/swaks/    //Perl。基于smtp的邮箱域名伪造测试工具。
- https://www.ehpus.com/post/smtp-injection-in-gsuite/    //基于smtp注入的邮件欺骗。
### 测试字典集
- https://github.com/FlameOfIgnis/Pwdb-Public/    //多语言恶意软件常用密码分析。goodjob。
- https://github.com/klionsec/SuperWordlist/    //实战沉淀下的各种弱口令字典
- https://github.com/tarraschk/richelieu    //.fr邮箱密码表
- https://github.com/TheKingOfDuck/fuzzDicts/    //Web Pentesting Fuzz 字典。G:/We5ter/Scanners-Box;G:/shack2/SNETCracker/dic;--
- https://github.com/danielmiessler/SecLists    //用户名，密码，URL，敏感数据模式，模糊测试负载，Web shell。G:/7dog7/bottleneckOsmosis;G:/Ridter/Pentest;G:/alpha1e0/pentestdb;--
- https://github.com/brannondorsey/PassGAN    //Py。深度学习，密码字典样本生成
- https://github.com/Saferman/cupper    //Py。根据用户习惯密码生成弱口令探测。G:/Mebus/cupp;G:/LandGrey/pydictor;--
- https://github.com/HongLuDianXue/BaiLu-SED-Tool    //pascal。白鹿社工字典生成器
- https://github.com/digininja/CeWL/    //Ruby。爬取目标网站关键词生成字典。
### 凭证扫描爆破
- https://github.com/vanhauser-thc/thc-hydra    //C。支持多种协议方式的破解与爆破.G:/scu-igroup/ssh-scanner;G:/lijiejie/htpwdScan;G:/ztgrace/changeme;G:/netxfly/crack_ssh;G:/euphrat1ca/F-Scrack;--
- https://github.com/maaaaz/thc-hydra-windows    //C。hydra的windows编译版本.
- https://github.com/shack2/SNETCracker    //C#。密码爆破工具，支持SSH、RDP、MySQL等常见协议,超级弱口令爆破工具.
- https://github.com/jmk-foofus/medusa    //C。快速并发模块化的端口爆破爆破工具。G:/awake1t/PortBrute;
- https://github.com/lanjelot/patator    //Py3。集成Hydra, Medusa, Ncrack, Metasploit modules and Nmap NSE验证爆破工具。
- https://github.com/nmap/ncrack    //C。Nmap协议弱口令爆破组件.
- https://github.com/galkan/crowbar    //Py。支持openvpn、rdp、ssh、vnc破解.G:/shengqi158/weak_password_detect;--
- https://github.com/ShawnDEvans/smbmap    //py。利用smb服务传递哈希、增删改查、命令执行、ip段共享枚举等。G:/m4ll0k/SMBrute;--
- https://github.com/InfosecMatter/Minimalistic-offensive-security-tools    //ps。smb、ad域密码爆破。
- https://github.com/3gstudent/SharpRDPCheck    //C#。RDP爆破验证，支持ntlm登录验证。G:/najachai/RDPUploader;--
- https://github.com/euphrat1ca/Fast-RDP-Brute-GUI-v2.0-by_Stas-M--Official/    //RDP密码爆破、扫描，Fast RDP Brute GUI by Stas M，stascorp.com解压密码Stas'M Corp.
- https://github.com/TunisianEagles/SocialBox    //针对fb、gmail、ins、twitter的用户名密码爆破的脚本.
- https://github.com/Moham3dRiahi/XBruteForcer    //perl。WordPress、Joomla、DruPal、OpenCart、Magento等CMS爆破。
- https://github.com/ryanohoro/csbruter/    //cobaltstrike服务密码爆破，3.10版本。
- https://github.com/theLSA/awBruter    //木马一句话爆破
### 密码破解哈希还原
- https://ophcrack.sourceforge.io/    //C。使用彩虹表Rainbow table来破解视窗操作系统下的LAN Manager散列（LM hash）的计算机程序。xp、vista
- https://securityxploded.com/download.php/    //各种密码方向安全小工具
- https://github.com/bdutro/ibm_pw_clear    //IBM x3550/x3560 M3 bios密码清除重置工具
- https://github.com/hashcat/hashcat    //C。哈希破解
- https://github.com/fireeye/gocrack    //Go。基于hashcat 3.6.0+的分布式密码破解工具
- https://github.com/s3inlc/hashtopolis    //php。hashcat的分布式破解工具，支持C#与python客户端
- https://github.com/chris408/known_hosts-hashcat    //Py。利用hashcat破解ssh密码hash
- https://github.com/clr2of8/DPAT    //Py。利用hashcat等工具域密码进行破解测试
- https://github.com/testsecer/Md5Decrypt    //C#。md5多接口查询基于网上web API的MD5搜索工具
- https://github.com/s0md3v/Hash-Buster    //调用多个API进行hash破解查询。
- https://github.com/magnumripper/JohnTheRipper    //C。开膛手john，已知密文的情况下尝试破解出明文的破解密码软件
- https://github.com/shinnok/johnny    //C++。John The Ripper Windows 界面GUI。
- https://www.52pojie.cn/thread-275945-1-1.html    //ARCHPR Pro4.54绿色中文破解版。压缩包密码破解，利用“已知明文攻击”破解加密的压缩文件
- https://github.com/thehappydinoa/iOSRestrictionBruteForce    //Py。实现的 ios 访问限制密码破解工具
- https://github.com/e-ago/bitcracker    //C。首款开源的BitLocker密码破解工具
- https://www.ru.nl/publish/pages/909282/draft-paper.pdf    //Intro。破解SSD下使用BitLocker加密
- https://github.com/fox-it/adconnectdump    //Py。Azure AD凭证导出工具
- https://github.com/DoubleLabyrinth/how-does-navicat-encrypt-password    //Navicate数据库密码解密
- https://github.com/TideSec/Decrypt_Weblogic_Password    //Java。解密weblogic密文
- https://github.com/MrSqar-Ye/wpCrack    //wordpress hash破解
- https://github.com/psypanda/hashID    //Py。对超过220种hash识别。使用'hash'
- https://github.com/AnimeshShaw/Hash-Algorithm-Identifier    //Py3。对超过160种hash识别。
- https://github.com/NetSPI/WebLogicPasswordDecryptor    //java,PS。WebLogic密码破解
### 在线密码破解
- https://www.cmd5.com/    //HASH密码在线破解。限制位数
- https://hashkiller.co.uk/Cracker    //密码破解。Google reCAPTCHA v3。
- http://hashtoolkit.com    //HASH密码在线破解。社区版
- http://md5.my-addr.com/md5_decrypt-md5_cracker_online/md5_decoder_tool.php    //md5密码破解。社区版。
- https://md5.gromweb.com/?md5=    //md5密码破解。社区版
- http://www.chamd5.org    //md5密码破解。需要登录
- http://www.xmd5.org    //md5密码破解。需要登录
- http://pmd5.com    //md5密码破解。需要验证码
- https://www.onlinehashcrack.com    //md5密码破解。需要验证码
## MITM攻击流量劫持
- https://github.com/bettercap/bettercap    //Go。中间人欺骗，网络攻击以及监控的瑞士军刀。该工具支持多种模块，比如中间人钓鱼框架、ARP/DNS欺骗、TCP以及数据包代理等。5K。GREATJOB。
- https://github.com/Binject/backdoorfactory    //Go。bettercap的二次开发拓展，用于将shellcode插入到网络上所有类型的二进制文件中。G:/secretsquirrel/the-backdoor-factory;--
- https://github.com/mitmproxy/mitmproxy    //Py。中间人攻击，支持SSL拦截，进行https流量代理。greatjob。15k。
- https://github.com/qiyeboy/BaseProxy    //Py3。异步http/https代理，楼上简化版。可以作为中间人工具，比如说替换网址图片等
- https://github.com/LionSec/xerosploit    //中间人攻击测试工具包
- https://github.com/infobyte/evilgrade    //一个模块化的脚本框架，使攻击者在不知情的情况下将恶意更新注入到用户更新中
- https://github.com/AlsidOfficial/WSUSpendu    //可以自主创建恶意更新，并将其注入到WSUS服务器数据库中，然后随意的分发这些恶意更新
- https://github.com/quickbreach/smbetray    //专注于通过文件内容交换、lnk交换来攻击客户端，以及窃取任何以明文形式传输的数据
- https://github.com/mrexodia/haxxmap    //对IMAP服务器进行中间人攻击
- https://github.com/SySS-Research/Seth    //PY3/BASH。Linux下MitM RDP远程服务中间人攻击。G:/citronneur/rdpy rdp远程服务模拟开启
- http://ntwox.sourceforge.net    //ntwow多协议伪造，网络测试工具集
- https://github.com/Ekultek/suddensix    //Bash。SLAAC（无状态地址自动配置）攻击自动化脚本，可用于在IPv4基础架构上构建IPv6覆盖网络，以执行中间人攻击。
### wifi中间人攻击
- https://github.com/wifiphisher/wifiphisher    //Py。中间人攻击，FakeAp恶意热点，WIFI钓鱼，凭证窃取。goodjob,7k。
- https://github.com/1N3/PRISM-AP    //自动部署RogueAP(恶意热点) MITM攻击框架
- https://github.com/sensepost/mana    //Wifi劫持工具，可以监听计算机或其他移动设备的Wifi通信，并能够模仿该设备
- https://github.com/deltaxflux/fluxion    //bash,Py。对使用wpa协议的无线网络进行MiTM攻击
- https://github.com/DanMcInerney/LANs.py    //Py。无线网络劫持ARP欺骗
### 硬件中间人攻击
- https://github.com/tenable/router_badusb    //利用路由器USE上网口和DHCP协议，使用树莓派连接VPN模拟流量转发进行中间人攻击
## 压测泛洪
- https://github.com/ywjt/Dshield    //Py。DDOS防护。
- http://www.yykkll.com    //压力测试站评测。W:defconpro.net;W:vip-boot.xyz;--
- https://rocketstresser.com/login.php    //多协议在线压测，支持cdn测试。
### 压力流量测试
- https://klionsec.github.io/2017/11/15/hping3/    //HPing3网络工具组包。P:LOIC;P:核武器CC-穿盾版;P:天降激光炮315;P:hyenae;--
- https://github.com/wg/wrk    //C。http流量测试。
- https://github.com/mschwager/dhcpwn    //Py。DHCP/IP压力测试。
- https://github.com/wenfengshi/ddos-dos-tools    //压力测试工具集
- https://github.com/Microsoft/Ethr    //Go。跨平台，TCP， UDP， HTTP， HTTPS压力测试工具
- https://github.com/Markus-Go/bonesi    //C。模拟僵尸网络进行ICMP/UDP/TCP/HTTP压测
- https://github.com/NewEraCracker/LOIC/    //C#,Mono。基于Praetox's LOIC project的压测工具。
- https://github.com/EZLippi/WebBench    //C。DDOS网站压力测试，最高并发3万
- https://github.com/IKende/Beetle.DT    //C#。分布式压力测试工具
- https://github.com/649/Memcrashed-DDoS-Exploit    //Py。利用shodan搜索Memcached服务器进行压力测试
### 压力拒绝服务
- https://github.com/ajmwagar/lor-axe    //Rust。多线程、低带宽消耗的HTTP DoS工具。G:/JuxhinDB/synner;--
- https://github.com/jseidl/GoldenEye    //Py。DOS攻击测试
- https://github.com/jagracey/Regex-DoS    //RegEx拒绝服务扫描器
- https://github.com/algo7/bluekeep_CVE-2019-0708_poc_to_exploit    //Py。RDP服务远程命令执行/DOS攻击/蓝屏exp。
- https://xz.aliyun.com/t/7895/    //techteach。利用WAF进行拒绝服务攻击。利用自动加载图片等资源文件的特性。
---
# 模糊测试漏洞挖掘
- https://github.com/euphrat1ca/security_w1k1/blob/master/wiki_Fuzzer.md/    //Fuzzer模糊测试。mywiki
# wiki_TowerDefence
- https://github.com/euphrat1ca/security_w1k1/blob/master/wiki_TowerDefence.md/    //安全体系防御，病毒后门查杀，系统监控，昏晓命令检测。mywiki
# wiki_MalwareSec
- https://github.com/euphrat1ca/security_w1k1/blob/master/wiki_MalwareSec.md/    //病毒分析、应急响应、恶意样本数据源收集库合集。mywiki
# wiki_FreeConnect
- https://github.com/euphrat1ca/security_w1k1/blob/master/wiki_FreeConnect.md/    //通讯工具技术相关.myWiki
# wiki_SelfServicerce
- https://github.com/euphrat1ca/security_w1k1/blob/master/wiki_SelfServicerce.md/    //自服务应用在线资源、文件\url\节点检测.myWiki
# wiki_TipSkill
- https://github.com/euphrat1ca/security_w1k1/blob/master/wiki_TipSkill.md/    //计算机技术相关.myWiki
# 渗透拓展利用
- https://github.com/euphrat1ca/security_w1k1/blob/master/wiki_ExpandAuth.md/    //远控、免杀、提权、维权、免杀、绕过。mywiki
# 无接触安全
- https://github.com/euphrat1ca/security_w1k1/blob/master/wiki_ContactlessSec.md/    //无线电/通讯WiFi/蓝牙/badusb 安全。mywiki
# 万物互联
- https://github.com/euphrat1ca/security_w1k1/blob/master/wiki_IoT&ICS.md/    //物联网/工业互联网 安全。mywiki
# 开源情报数据源分析
- https://github.com/euphrat1ca/security_w1k1/blob/master/wiki_OsintData.md/    //开源情报数据源分析.mywiki
# 端口转发流量代理
- https://github.com/euphrat1ca/security_w1k1/blob/master/wiki_SocketProxy.md    //端口映射，代理穿透，流量代理转发
# 欺骗防御
- https://github.com/euphrat1ca/security_w1k1/blob/master/wiki_HoneyPot.md.md/    //欺骗防御、蜜罐、主动反制。myWiki
# 逆向安全分析
- https://github.com/euphrat1ca/security_w1k1/blob/master/wiki_SecReverse.md/    //逆向分析、反编译、破解。myWiki
# 漏洞收集
- https://github.com/euphrat1ca/security_w1k1/blob/master/wiki_VulExp.md/    //web漏洞、软件模板漏洞、数据库、中间件、CMS框架漏洞、MS&Linux等系统组件漏洞、IOT漏洞收集表单。myWiki
# Web安全前端利用
- https://github.com/euphrat1ca/security_w1k1/blob/master/wiki_WebSecurity.md/    //web安全测试利用、前端安全、数据库sql注入、xss跨站、上传漏洞、命令注入执行、webshell、https证书加密、web应用扫描器框架。myWiki。
# 应用安全利用
- https://github.com/euphrat1ca/security_w1k1/blob/master/wiki_AppSecurity/    //移动端APP，应用代码审计。myWiki。
# 拓展插件相关工具
- https://github.com/euphrat1ca/security_w1k1/blob/master/wiki_ToolDevelop.md/    //kali/nmap/burpsuite/Nessus/awvs/sqlmap/metasploit/cobaltstrike/empire/菜刀/ 插件。mywiki
<br>
TheEnd