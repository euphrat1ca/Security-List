***项目简介***
根据中华人民共和国《网络安全法》相关政策规定，本文章只做学习测试，不被允许通过本文章技术手段进行非法行为，使用技术的风险由您自行承担(The author does not assume any legal responsibility.)<br>
&emsp;&emsp;https://github.com/euphrat1ca/security_w1k1 //Have to say,the index is in my mind<br>
&emsp;&emsp;一个 Red Team 攻击的生命周期，整个生命周期包括：信息收集、攻击尝试获得权限、持久性控制、权限提升、网络信息收集、横向移动、数据分析（在这个基础上再做持久化控制）、在所有攻击结束之后清理并退出战场（扫尾）。<br>
&emsp;&emsp;几千行的项目有点过于庞大，于是在第两百次更新的时候，选择把一些较为频繁的持续更新内容分到其它文件内。<br>
分类标签：mywiki;intro;工具手册;通讯技术工具;威胁情报;恶意样本;自服务应用;研究技术;漏洞利用;Web安全;<br>
导航标签：一个人的安全部;Awesome系列;类似于*架构;<br>
类型标签：模拟测试;* Kali系统类;* ATT&CK矩阵类;作者拼音;Github:/\Web:\Page:\Connect;常见缩写;<br>
状态标签：simple;noupdate;商业版;社区版;<br>
测评标签：testjob;welljob;goodjob;greatjob;<br>
# 安全相关资源列表
- https://arxiv.org    //康奈尔大学（Cornell University）开放文档
- https://github.com/sindresorhus/awesome    //awesome系列
- http://www.owasp.org.cn/owasp-project/owasp-things    //OWASP项目
- https://github.com/SecWiki/sec-chart    //安全思维导图集合。G：Mayter/sec-charts;--
- https://github.com/Ascotbe/Osmographic-brain-mapping    //安全思维脑图。ctf/web/二进制/ai/区块链/业务/主机/社工/移动/无线/运维/风控
- https://github.com/tom0li/collection-document    //安全部/攻防/内网/Web/apt/漏洞预警/开发/Bug Bounty/SDL/SRC
- https://github.com/secure-data-analysis-data-sharing/data-analysis    //资料分为安全态势、攻防对抗、数据分析、威胁情报、应急响应、物联网安全、企业安全建设、其他书籍八部分
- https://github.com/hongriSec/AI-Machine-Learning-Security    //机器学习算法、AI模型、渗透测试工具
- https://github.com/bt3gl/Pentesting-Toolkit    //CTF、逆向、移动端、网络安全、web安全、工具使用。welljob。
- http://paper.tidesec.com/    //免杀bypass、红蓝ctf、ics、iot、移动、应急响应、代码审计、工具设计
## 安全建设方案
- https://www.nist.gov/topics/cybersecurity    //美国国家标准与技术研究院。NVD漏洞库
- https://www.mitre.org/publications/all    //mitre安全机构。CVE漏洞库
- https://www.alibabacloud.com/blog    //阿里安全建设
- https://security.tencent.com/index.php/blog/msg/139    //腾讯安全建设。网络空间安全时代的红蓝对抗建设
- https://github.com/baidu-security    //百度安全建设
- https://ai.google/research/pubs/?area=SecurityPrivacyandAbusePrevention    //谷歌安全建设
- https://aws.amazon.com/cn/blogs/security/    //亚马逊安全建设
- https://code.fb.com/category/security/    //Facebook安全建设
- http://www.freebuf.com/articles/ics-articles/178822.html    //浅析煤炭企业如何进行工控安全建设
- https://www.sec-un.org/金融业企业安全建设之路/    //金融业企业安全建设之路。niejun
- https://blogs.cisco.com/tag/ios-security    //思科网络设备操作维护系统IOS（互联网操作系统Internetwork Operating System）
- 公众号：终端安全运营年度笔记    //
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
## 安全基础科普培训
- https://book.yunzhan365.com/umta/rtnp/mobile/index.html    //网络安全科普小册子
- http://sec.cuc.edu.cn/huangwei/textbook/ns/    //网络安全电子版教材。中传信安课程网站
- https://ilearningx.huawei.com/portal/#/portal/EBG/26    //华为e学云。安全科普
- https://keenlab.tencent.com/zh/index.html    //腾讯科恩实验室
- https://github.com/ym2011/SecurityManagement    //分享安全管理体系、ISO27001、等级保护、安全评审的经验。
- https://space.bilibili.com/37422870    //安全入门视频
- https://space.bilibili.com/406898187/channel/detail?cid=85655    //安全帮内网高级加固课程
- https://github.com/tiancode/learn-hacking    //入门网络安全
- https://null-byte.wonderhowto.com    //msf/fb/wifi/pass/取证/social/信息收集
- https://github.com/knownsec/RD_Checklist    //知道创宇技能列表
- https://github.com/ChrisLinn/greyhame-2017    //灰袍技能书2017版本
### 安全大会资料
- https://www.hackinn.com/search/?keyword=    //资料站。W:srxh1314.com/;W:infocon.org/;W:vipread.com/;--
- http://www.irongeek.com/i.php?page=security/hackingillustrated    //国内外安全大会相关视频与文档
- https://github.com/knownsec/KCon    //KCon大会文章PPT。P:/blackhat黑帽大会;--
### 使用手册指南
- https://www.cnblogs.com/backlion/p/10616308.html    //Coablt strike官方教程中文译版本
- https://github.com/aleenzz/Cobalt_Strike_wiki    //Cobalt Strike系列 教程使用
- http://www.hackingarticles.in/comprehensive-guide-on-hydra-a-brute-forcing-tool/    //hydra使用手册
- https://www.gitbook.com/book/t0data/burpsuite/details    //burpsuite实战指南
- https://zhuanlan.zhihu.com/p/26618074    //Nmap扩展脚本使用方法
- https://github.com/hardenedlinux/linux-exploit-development-tutorial    //Linux exploit 开发入门
- https://wizardforcel.gitbooks.io/asani/content    //浅入浅出Android安全 中文版
- https://wizardforcel.gitbooks.io/lpad/content    //Android 渗透测试学习手册 中文版
- https://github.com/hookmaster/frida-all-in-one/    //《FRIDA操作手册》
### Offensive Security指南
- https://wizardforcel.gitbooks.io/kali-linux-web-pentest-cookbook/content/    //Kali Linux Web渗透测试秘籍 中文版
- https://www.offensive-security.com/metasploit-unleashed/    //kali出的metasploit指导笔记
#### OSCP渗透测试
- https://github.com/anandkumar11u/OSCP-60days    //OSCP All Tools
- https://github.com/neal1991/OSCP_learing    //oscp learning。tools、command
- https://github.com/foobarto/redteam-notebook    //OSCP-EXAM 红队标准渗透测试流程+常用命令
- https://github.com/gajos112/OSCP    //OSCP-EXAM
- https://github.com/RustyShackleford221/OSCP-Prep    //OSCP-EXAM
- https://github.com/lsh4ck/oscp    //oscp历程。lshack.cn备战
- https://0xdarkvortex.dev/index.php/2018/04/17/31-days-of-oscp-experience/    //31 days of OSCP Experience
#### OSCE漏洞挖掘
- https://www.freebuf.com/news/206041.html    //中文首发丨OSCE（Offensive Security Certified Expert）考证全攻略
- https://github.com/ihack4falafel/OSCE    //
- https://github.com/dhn/OSCE    //
- https://github.com/73696e65/windows-exploits    //
## 安全运维
- https://github.com/aqzt/kjyw    //快捷运维，代号kjyw，项目基于shell、python，运维脚本工具库，收集各类运维常用工具脚本，实现快速安装、快速配置策略等。安全专题
- https://github.com/openspug/spug/    //JS,Py。轻量级无Agent的自动化运维平台，整合了主机管理、主机批量执行、主机在线终端、文件在线上传下载、应用发布部署、在线任务计划、配置中心、监控、报警等功能。
### 等保安全
- https://mp.weixin.qq.com/s/gcohsAQSHHCVoG-HlYYaeg    //公众号：等级保护测评方法（精华版）
### 运维手册
- https://www.cisecurity.org/cis-benchmarks/    //CIS总结的140多种配置基准
- https://github.com/aqzt/sso    //服务器安全运维规范（Server security operation）
- https://github.com/imthenachoman/How-To-Secure-A-Linux-Server    //Linux服务器保护。9k
- https://github.com/trimstray/nginx-admins-handbook    //nginx操作手册。8k
- https://github.com/valentinxxx/nginxconfig.io/    //在线nginx配置文件生成，W:nginxconfig.io;--
### 系统检查基线
- https://www.open-scap.org/    //安全基线评估工具集
- https://github.com/re4lity/Benchmarks    //常用服务器、数据库、中间件安全配置基线 ，基本包括了所有的操作系统、数据库、中间件、网络设备、浏览器、安卓、IOS、云服务的安全配置。
- https://github.com/Jsitech/JShielder    //linux下服务器一键加固脚本
- https://github.com/trimstray/linux-hardening-checklist    //Linux服务器加固基线
- https://github.com/a13xp0p0v/kconfig-hardened-check    //用于检查 Linux 内核配置中的安全加固选项的脚本
- https://gist.github.com/mackwage/08604751462126599d7e52f233490efe    //Windows安全加固命令
- https://github.com/wstart/DB_BaseLine    //数据库基线检查工具
- https://github.com/drduh/macOS-Security-and-Privacy-Guide    //Py。MacOS安全性基线。
### 安全测试速查表
- https://github.com/HarmJ0y/CheatSheets    //多个工具速查手册（Beacon / Cobalt Strike，PowerView，PowerUp，Empire和PowerSploit）
- https://github.com/louchaooo/kali-tools-zh    //kali工具使用手册
- https://github.com/b1n4ry4rms/RedTeam-Pentest-Cheatsheets/    //常见工具命令
- https://github.com/EvilAnne/Violation_Pnetest    渗透红线Checklist
- https://www.octority.com/pepenote/    //10w行渗透测试技巧
- https://book.hacktricks.xyz/    //端口漏洞对应，渗透命令，提权技巧。goodjob。
- https://mp.weixin.qq.com/s/y3IdYSIDckQTaPgNQMS7Cg    //公众号：常见端口渗透笔录
- http://tool.oschina.net/commons/    //常用对照表，HTTP Content-type、TCP/UDP常见端口参考、字体、颜色等。
- https://tool.oschina.net/commons/    //常用对照表。http文件类型、转码、转义、端口、状态码、字体。
### 安全测试checklist
- https://github.com/juliocesarfort/public-pentesting-reports    //由几家咨询公司和学术安全组织发布的公共渗透测试报告的列表。
- http://pentestmonkey.net/category/cheat-sheet    //渗透测试常见条目
- https://github.com/0xRadi/OWASP-Web-Checklist    //owasp网站检查条目
- https://github.com/arunmagesh/hw_hacking_cheatsheet    硬件hardware测试条目
- https://mp.weixin.qq.com/s/O36e0gl4cs0ErQPsb5L68Q    //公众号：区块链、以太坊智能合约审计 CheckList
- https://github.com/slowmist/eos-bp-nodes-security-checklist    //区块链，EOS bp nodes security checklist（EOS超级节点安全执行指南）
- https://github.com/GitGuardian/APISecurityBestPractices    //api接口测试checklist
- https://github.com/shieldfy/API-Security-Checklist    //api开发核对清单。12k。
- https://github.com/theLSA/CS-checklist    //CS客户端检查条目checklist
- https://github.com/theLSA/hack-cs-tools    //CS客户端测试工具，配合客户端checklist
- https://xz.aliyun.com/t/2089    //金融科技SDL安全设计checklist
- 汽车安全测试Checklist    //水滴安全实验室
- https://blog.csdn.net/qq_39541626/article/details/104891590    //小程序、公众号安全测试list
- https://www.butian.net/School/content?id=307/    //移动通信网络渗透测试科普
### 安全测试辅助
- https://github.com/feross/SpoofMAC    //Py。跨平台mac修改。
- https://github.com/opensec-cn/vtest    //Py。用于辅助安全工程师漏洞挖掘、测试、复现，集合了mock、httplog、dns tools、xss，可用于测试各类无回显、无法直观判断或特定场景下的漏洞。
- https://github.com/medbenali/CyberScan    //Py。渗透测试辅助工具。支持分析数据包、解码、端口扫描、IP地址分析等。
- https://github.com/ismailtasdelen/hackertarget    //Py。Use open source tools and network intelligence to help organizations with attack surface discovery and identification of security vulnerabilities.
- https://github.com/ultrasecurity/webkiller    //Py。渗透辅助。ip信息、端口服务指纹、蜜罐探测、bypass cloudflare。
- https://github.com/alienwithin/OWASP-mth3l3m3nt-framework    //渗透辅助，php，exp搜寻、payload与shell生成、信息收集
- https://github.com/foryujian/ipintervalmerge    //IP合并区间
## IPv6安全相关
- https://github.com/sfan5/fi6s    //ipv6端口快速扫描器
- https://github.com/fgont/ipv6toolkit    //C。si6networks.com组织的ipv6工具集
- https://github.com/lavalamp-/ipv666    //Go。ipv6地址枚举扫描
- https://github.com/christophetd/IPv6teal    //Py。利用ipv6隐蔽隧道传输数据
## 区块链安全
- https://github.com/quoscient/octopus    //区块链智能合约安全分析工具
- https://github.com/ConsenSys/mythril-classic    //用于以太坊智能协议的安全分析工具
## 云安全相关
- https://cloud.tencent.com/developer/article/1621185    //【云原生攻防研究】针对容器的渗透测试方法
- https://github.com/dafthack/CloudPentestCheatsheets/    //云渗透备忘单，云服务检查清单
- https://github.com/brompwnie/botb    //Go。BOtB容器安全分析和脆弱点利用工具。利用CVE-2019-5736、DockerSocket或特权模式进行容器逃逸。
### Kubernetes集群安全
- https://github.com/aquasecurity/kube-hunter    //Py。采用了KHV + 数字进行漏洞编号，云原生环境Kubernetes框架漏洞扫描工具。W:info.aquasec.com/kubernetes-security;--
- https://github.com/inguardians/peirates    //Go。Kubernetes集群的渗透测试工具，专注于权限提升和横向移动。
- https://github.com/kabachook/k8s-security/    //bash/Py。Kubernetes安全集合
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
## 攻防资源学习
- https://attack.mitre.org    //mitre科技机构对攻击技术的总结wiki，攻击矩阵模型。
- https://github.com/infosecn1nja/awesome-mitre-attack    //Mitre ATT&CK™框架资源收集。Web:huntingday.github.io //MITRE | ATT&CK-CN 中文站;G:/lengjibo/ATT-CK-CN //attck实操实验记录;W:vulhub.org.cn/attack //清华林妙倩 att ck汉化;G:/NomadCN112/Chinese-translation-ATT-CK-framework;--
- https://github.com/Micropoor/Micro8    //Microporor高级攻防100课。goodjob。PHP安全新闻早8点课程
- https://github.com/meitar/awesome-cybersecurity-blueteam    // A curated collection of awesome resources, tools, and other shiny things for cybersecurity blue teams.
- https://bitvijays.github.io    //infosec知识总结。goodjob。
- https://github.com/Mel0day/RedTeam-BCS    //BCS（北京网络安全大会）2019 红队行动会议重点内容，详细步骤。goodjob。
- https://github.com/Snowming04/The-Hacker-Playbook-3-Translation    //[译] 渗透测试实战第三版(红队版)The Hacker Playbook 3
- https://github.com/OWASP/OWASP-Testing-Guide-v5    //OWASP 发布的渗透测试指南文档
- https://github.com/jeansgit/RedTeam    //RedTeam资料收集整理。红蓝对抗资料分享，红蓝对抗相关图片，内网安全渗透总结
- https://github.com/yeyintminthuhtut/Awesome-Red-Teaming    //优秀红队资源列表
- https://github.com/Kinimiwar/Penetration-Testing    //渗透测试方向优秀资源收集
- https://github.com/jshaw87/Cheatsheets    //渗透测试/安全秘籍/笔记
- http://www.pentest-standard.org/index.php/Pre-engagement    //渗透测试标准-渗透项目实施前的互动。项目实施前
- https://github.com/r35tart/Penetration_Testing_Case    //攻防测试案例
### 学习社工综合利用
- https://www.freebuf.com/articles/102500.html    //黑客讲述渗透Hacking Team全过程（详细解说）
- https://github.com/myselfexplorer/hackingLibrary    //社工大佬的笔记手册
- https://payloads.online/archivers/2019-05-21/1    //鱼叉攻击-尝试。qingxuan
- https://github.com/shegongbook/shegonganli    //社工案例
### 学习Web漏洞攻防
- https://portswigger.net/web-security    //burpsuite官方web安全材料与实验室。testjob。
- https://github.com/irsdl/top10webseclist/    //十大网络黑客技术列表
- https://wizardforcel.gitbooks.io/web-hacking-101/content    //Web Hacking 101 中文版
- https://websec.readthedocs.io/zh/latest/    //Web安全学习笔记
- https://techvomit.net/web-application-penetration-testing-notes/    //web渗透测试笔记
- https://github.com/qazbnm456/awesome-web-security    //Web安全资料和资源列表
- https://www.lynda.com/JavaScript-tutorials/What-server-side-JavaScript-injection-SSJI/797717/5025838-4.html    //SSJI服务的JavaScript注入
- https://www.imperva.com/blog/nosql-ssji-authentication-bypass/    //Imperva WAF墙公司关于，SSJI服务的JavaScript注入
### 学习内网安全后渗透
- https://attack.mitre.org/wiki/Lateral_Movement    //mitre机构对横向移动的总结
- https://github.com/l3m0n/pentest_study    //从零开始内网渗透学习。G:/Ridter/Intranet_Penetration_Tips;-
- https://github.com/uknowsec/Active-Directory-Pentest-Notes    //个人域渗透学习笔记，配合域环境搭建。goodjob。
- https://klionsec.github.io/2016/08/10/ntlm-kerberos/    //深刻理解windows安全认证机制 [ntlm & Kerberos]。W:彻底理解Windows认证 - 议题解读;公众号：域渗透 | Kerberos攻击速查表;P:/Kerberos的白银票据详解/Kerberos的黄金票据详解;
- https://daiker.gitbook.io/windows-protocol    //内网域基础协议分析系列文章。本系列文章将针对内网渗透的常见协议Windows凭证利用(如kerbeos,ntlm,smb,ldap等)进行协议分析，相关漏洞分析以及漏洞工具分析利用。
- https://github.com/infosecn1nja/AD-Attack-Defense    //AD活动目录攻击链与防御
- https://github.com/nccgroup    //国外安全咨询团队，burp插件的编写、内网利用工具、app安全工具
- https://adsecurity.org    //Active Directory安全攻防。goodjob。
- https://3gstudent.github.io    //AD域渗透/DNS/可信目录/横向移动。G:/klionsec.github.io;--
- https://www.anquanke.com/post/id/87976    //Powershell攻击指南黑客后渗透之道系列——基础篇\进阶利用\实战篇
# 技术利用套件集合
- https://github.com/infosecn1nja/Red-Teaming-Toolkit    //红队攻击生命周期，开源和商业工具。goodjob。
- https://github.com/redcanaryco/atomic-red-team    //Atomic Red Team团队关于win、linux、mac等多方面apt利用手段、技术与工具集。2k。
- https://github.com/blaCCkHatHacEEkr/PENTESTING-BIBLE    //红队工具、攻击手段
- https://github.com/toolswatch/blackhat-arsenal-tools    //blackhat工具集
- https://github.com/demonsec666/Security-Toolkit    //渗透攻击链中常用工具及使用场景
- https://github.com/n00py/ReadingList/blob/master/gunsafe.txt    //安全工具集
- https://github.com/Z4nzu/hackingtool    //Linux安全工具集合，类似于pentestbox架构
## 安全测试系统集合
- https://www.parrotsec.org    //鹦鹉安全操作系统。pentest kali系统类。
- https://tails.boum.org/index.en.html    //tails匿名操作系统。pentest kali系统类。
- https://github.com/fireeye/commando-vm    //FireEye开源Commando VM，专为红队（pen-testing）定制的Windows。W:blackwin.ir //win-kali系统类;--
## Windows利用工具集合
- https://github.com/BlackDiverX/cqtools    //Windows利用工具集
- https://github.com/RcoIl/CSharp-Tools    //安全测试CSharp - 工具集。编码转换、navicat密码抓取、weblogic反序列化、信息搜集、DES解密、机器类型判断、远程利用、C段标题WebTitle。
- https://github.com/microsoft/WindowsProtocolTestSuites    //C#。针对Windows开发规范的Windows协议测试套件。
- https://github.com/k8gege/    //K8工具合集(内网渗透/提权工具/远程溢出/漏洞利用/扫描工具/密码破解/免杀工具/Exploit/APT/0day/Shellcode/Payload/priviledge/BypassUAC/OverFlow/WebShell/PenTest) Web GetShell Exploit(Struts2/Zimbra/Weblogic/Tomcat/Apache/Jboss/DotNetNuke/zabbix)。P:/cnblogs.com/k8gege，常见解压密码Kk8team\Kk8gege。
- https://github.com/3gstudent/Homework-of-C-Sharp/    //C#。三好学生文章工具、脚本。
## 信息隐匿保护
- https://github.com/ffffffff0x/Digital-Privacy/    //一个关于数字隐私搜集、保护、清理集一体的方案,外加开源信息收集(OSINT)对抗。类wiki_OsintData；wiki_SelfServicerce；wiki_FreeConnect。goodjob。
- https://github.com/leitbogioro/Fuck_Aliyun    //关闭阿里云监控服务
- https://github.com/Nummer/Destroy-Windows-10-Spying    //DWS用来关闭windows监控服务
- https://www.anquanke.com/post/id/195011    //暗度陈仓：基于国内某云的 Domain Fronting 技术实践。CDN域前置
- https://www.freebuf.com/sectool/232555.html    //利用Cloudflare Worker来隐藏C2基础设施。CDN域前置。G:/Berkeley-Reject/workers-proxy;--
### 隐匿流量洋葱路由
- https://www.torproject.org/    //洋葱浏览器。P:/dnmugu4755642434.onion/ kilos搜索引擎;--
- https://github.com/globaleaks/Tor2web    //darkweb暗网代理服务器，将onion的服务变为普通的服务
- https://github.com/milesrichardson/docker-onion-nmap    //使用nmap扫描Tor网络上隐藏的"onion"服务
- https://github.com/GouveaHeitor/nipe    //一个使所有流量通过Tor网络发出的脚本
- https://github.com/Edu4rdSHL/tor-router    //Bash。使用tor代理全部流量。dnsleaktest.com dns检测。
- https://github.com/trimstray/multitor    //Bash。启用多个TorBrowser通道转发流量，并设置负载均衡
- https://github.com/NullArray/NetSet    //Bash。终端多路复用器，其会话通过Tor路由，并通过自动安装和配置DNSCrypt-proxy来保护DNS流量。
### 容器安全
- https://vulnerablecontainers.org    //对公开docker容器镜像漏洞扫描，并标出CVE号
- https://github.com/P3GLEG/WhaleTail    //根据docker镜像生成成dockerfile
- https://github.com/cr0hn/dockerscan    //docker扫描工具
- https://github.com/knqyf263/trivy    //Go。针对容器的漏洞扫描器.2K。
### 测试字典集
- https://github.com/FlameOfIgnis/Pwdb-Public/    //多语言恶意软件常用密码分析。goodjob。
- https://github.com/klionsec/SuperWordlist/    //实战沉淀下的各种弱口令字典
- https://github.com/tarraschk/richelieu    //.fr邮箱密码表
- https://github.com/TheKingOfDuck/fuzzDicts/    //Web Pentesting Fuzz 字典。G:/xmendez/wfuzz/tree/master/wordlist;G:/We5ter/Scanners-Box;G:/shack2/SNETCracker/dic;--
- https://github.com/danielmiessler/SecLists    //用户名，密码，URL，敏感数据模式，模糊测试负载，Web shell。G:/7dog7/bottleneckOsmosis;G:/Ridter/Pentest;G:/alpha1e0/pentestdb;--
- https://github.com/brannondorsey/PassGAN    //Py。深度学习，密码字典样本生成
- https://github.com/Saferman/cupper    //Py。根据用户习惯密码生成弱口令探测。G:/Mebus/cupp;G:/LandGrey/pydictor;--
- https://github.com/HongLuDianXue/BaiLu-SED-Tool    //pascal。白鹿社工字典生成器
- https://github.com/digininja/CeWL/    //Ruby。爬取目标网站关键词生成字典。
## 社工相关
- https://github.com/mehulj94/Radium-Keylogger    //py.键盘记录工具。
- https://github.com/ggerganov/kbd-audio    //C++。linux下利用麦克风监控键盘输入测试输入值。
- https://github.com/Pickfordmatt/SharpLocker/    //c#。Windows锁屏密码记录。G:/bitsadmin/fakelogonscreen;PS:Invoke-LoginPrompt.ps1;PS:Invoke-CredentialsPhish.ps1;Koadic:password_box;Empire:collection/toasted;Empire:collection/prompt;MSF:phishwindowscredentials;--
- https://github.com/thelinuxchoice/lockphish    //shell,PHP。基于ngrok利用钓鱼网站获取锁屏密码（手机、电脑）。
- https://github.com/threatexpress/domainhunter    //检查过期域名，bluecoat分类和Archive.org历史记录，以确定最为适合于钓鱼和C2的域名。
- https://github.com/Mr-Un1k0d3r/CatMyPhish    //收集目标类似于的尚未注册的域名。
- https://github.com/thinkst/canarytokens    //Py。重要文件的追踪溯源，信标定位（canarytokens.org/generate#）服务端代码。蜜标
- https://github.com/Viralmaniar/I-See-You    //Bash。利用公网网站代理获取用户的真实地理信息。simple
- https://www.jianshu.com/p/147cf5414851    //聊聊那些常见的探侦类APP
### 网站克隆
- http://www.httrack.com    //网站克隆镜像
- https://github.com/JonCooperWorks/judas    //Go。克隆网站钓鱼
### 钓鱼框架
- https://github.com/bhdresh/SocialEngineeringPayloads    //负责收集用于证书盗窃和鱼叉式网络钓鱼攻击的社交工程技巧和payloads
- https://github.com/trustedsec/social-engineer-toolkit    //Py。TrustedSec开发的专为社交工程设计的开源渗透测试框架,SET框架支持网站克隆、邮件伪造、反弹shell等
- https://github.com/thelinuxchoice/blackeye    //Py。拥有facebook、instagram等三十余个钓鱼模板的一键启用工具
- https://github.com/M4cs/BlackEye-Python    //Py。以blackeye为基础，增加子域名模拟伪造功能
- https://github.com/gophish/gophish    //Go。拥有在线模板设计、发送诱骗广告等功能的钓鱼系统
- https://github.com/L4bF0x/PhishingPretexts    //钓鱼模板
- https://github.com/drk1wi/Modlishka    //Go。网络钓鱼工具
- https://github.com/azizaltuntas/Camelishing    //Py3。界面化社会工程学攻击辅助工具
- https://github.com/tatanus/SPF    //Py3。deefcon上的钓鱼系统
- https://github.com/MSG-maniac/mail_fishing    //PHP。基于thinkphp的甲方邮件钓鱼系统
- https://github.com/samyoyo/weeman    //钓鱼的http服务器
- https://github.com/Raikia/FiercePhish    //可以管理所有钓鱼攻击的完整钓鱼框架，允许你跟踪单独的网络钓鱼活动，定时发送电子邮件等
- https://github.com/securestate/king-phisher    //可视化钓鱼活动工具包
- https://github.com/fireeye/ReelPhish    //实时双因素网络钓鱼工具
- https://github.com/kgretzky/evilginx2/    //登录页面钓鱼，绕过双因素认证等
- https://github.com/ustayready/CredSniper    //使用Flask和Jinja2模板编写的网络钓鱼框架，支持捕获2FA令牌
- https://github.com/n0pe-sled/Postfix-Server-Setup    //自动化建立一个网络钓鱼服务器
- https://github.com/fireeye/PwnAuth    //OAuth滥用测试检测平台
### 邮件伪造
- https://emkei.cz    //在线邮件伪造。多功能模拟。W:tool.chacuo.net/mailanonymous;--
W:ns4gov.000webhostapp.com;W:smtp2go.com/;--
- https://github.com/Macr0phag3/email_hack    //Py。钓鱼邮件伪造。G:/lunarca/SimpleEmailSpoofer;G:/Dionach/PhEmail;--
- https://www.jetmore.org/john/code/swaks/    //Perl。基于smtp的邮箱域名伪造测试工具。
- https://www.ehpus.com/post/smtp-injection-in-gsuite/    //基于smtp注入的邮件欺骗。
### 凭证扫描爆破
- https://github.com/vanhauser-thc/thc-hydra    //C。支持多种协议方式的破解与爆破.G:/scu-igroup/ssh-scanner;G:/lijiejie/htpwdScan;G:/ztgrace/changeme;G:/netxfly/crack_ssh;G:/euphrat1ca/F-Scrack;--
- https://github.com/maaaaz/thc-hydra-windows    //C。hydra的windows编译版本.
- https://github.com/shack2/SNETCracker    //C#。密码爆破工具，支持SSH、RDP、MySQL等常见协议,超级弱口令爆破工具.
- https://github.com/jmk-foofus/medusa    //C。快速并发模块化的登陆爆破工具。
- https://github.com/lanjelot/patator    //Py3。集成Hydra, Medusa, Ncrack, Metasploit modules and Nmap NSE验证爆破工具。
- https://github.com/nmap/ncrack    //C。Nmap协议弱口令爆破组件.
- https://github.com/galkan/crowbar    //Py。支持openvpn、rdp、ssh、vnc破解.G:/shengqi158/weak_password_detect;--
- https://github.com/ShawnDEvans/smbmap    //py。利用smb服务传递哈希、增删改查、命令执行、ip段共享枚举等。G:/m4ll0k/SMBrute;--
- https://github.com/InfosecMatter/Minimalistic-offensive-security-tools    //ps。smb、ad域密码爆破。
- https://github.com/3gstudent/SharpRDPCheck    //C#。RDP爆破验证，支持ntlm登录验证。G:/najachai/RDPUploader;--
- https://github.com/euphrat1ca/Fast-RDP-Brute-GUI-v2.0-by_Stas-M--Official/    //RDP密码爆破、扫描，Fast RDP Brute GUI by Stas M，stascorp.com解压密码Stas'M Corp.
- https://github.com/TunisianEagles/SocialBox    //针对fb、gmail、ins、twitter的用户名密码爆破的脚本.
- https://github.com/Moham3dRiahi/XBruteForcer    //perl。WordPress、Joomla、DruPal、OpenCart、Magento等CMS爆破。
- https://github.com/ryanohoro/csbruter/    //cobaltstrike服务密码爆破，3.10版本
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
- https://github.com/s0md3v/Hash-Buster    //能调用多个API进行hash破解查询的智能工具
- https://github.com/magnumripper/JohnTheRipper    //C。开膛手john，已知密文的情况下尝试破解出明文的破解密码软件
- https://github.com/shinnok/johnny    //C++。John The Ripper Windows GUI界面。
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
## CTF相关(Capture The Flag)
- https://ctftime.org    //CTF排名比赛介绍
- https://github.com/apsdehal/awesome-ctf    //frameworks, libraries, resources, softwares and tutorials。
- https://ctf-wiki.github.io/ctf-wiki/    //CTFwiki，Misc/Crypto/Web/Assembly/Executable/Reverse/Pwn/Android/ICS。
- https://firmianay.gitbooks.io/ctf-all-in-one    //CTF-All-In-One 《CTF 竞赛入门指南》。西电信安协会
- https://www.butian.net/School    //补天培训。CTF/攻防/硬件/社工/开发/代码审计。goodjob。G:/imsebao/Code-Audit //代码审计;--
- https://github.com/Hacker0x01/hacker101    //Ruby。hacker one联名的Web攻防教学，有ctf靶场和视频.10K
### CTF解题思路
- 公众号：VulnHub通关日记-DC_    //vulnhub write up系列
- https://github.com/susers/Writeups  //国内玩各大CTF赛题及writeup整理。Github:/hongriSec/CTF-Training;Github:/balsn/ctf_writeup;--
- https://github.com/balsn/ctf_writeup    //CTF writeups from Balsn
### CTF靶场平台
- https://github.com/facebook/fbctf    //HACK,PHP。CTF比赛平台搭建。
- https://github.com/CTFd/CTFd    //py2。基于flask的动态Capture The Flag framework
- https://github.com/zhl2008/awd-platform    //AWD攻防比赛平台。
- https://github.com/wuhan005/Asteroid/    //C#。CTF AWD 实时 3D 攻击大屏
- https://github.com/vidar-team/Cardinal/    //Go。CTF⛳️ AWD (Attack with Defense) 线下赛平台
- https://github.com/gabemarshall/microctfs    //SHELL,JS。小型ctf镜像docker
- https://github.com/giantbranch/pwn_deploy_chroot    //Py。部署多个pwn题到一个docker容器中
- https://github.com/PELock/CrackMeZ3S-CTF-CrackMe-Tutorial    //C++。为CTF比赛编写CrackMe软件。
- https://github.com/m0xiaoxi/AWD_CTF_Platform    //CTF-AWD 训练平台
### CTF命令脚本
- https://github.com/adon90/pentest_compilation    //ctf比赛与OSCP考试中常见的知识点和命令
- https://edwardchoijc.github.io/CTF线下AWD经验总结.html/    //CTF攻防AWD经验总结
- https://github.com/NEALWE/AWD_FrameWork    //Py3。awd框架，比赛常用脚本。
- https://github.com/Wfzsec/awd_attack_framework    //PHP。AWD(Attack With Defense,攻防兼备)常用脚本+不死马+crontab+防御方法。
### CTF杂项
- https://www.wishingstarmoye.com/ctf/autokey    //CTF在线工具集合。密码/隐写/二维码/哈希/编码/激战2？？？/。
- https://github.com/bugsafe/WeReport    //PHP。WeReport报告助手，一键生成测试报告。
### CTF密码学
- https://github.com/0Chencc/CTFCrackTools    //kotlin与java。CTF工具框架，支持Crypto，Mis等。后期以编写python插件增强功能。
- https://github.com/guyoung/CaptfEncoder    //Nodejs。基于Electron。跨平台网络安全工具套件，提供网络安全相关编码转换、古典密码、密码学、特殊编码等工具，并聚合各类在线工具。
- https://github.com/gchq/CyberChef    //JS。反混淆，密码解密工具。
- https://github.com/3summer/CTF-RSA-tool    //Py3。ctf rsa套路。
### CTF隐写术
- https://www.freebuf.com/sectool/208781.html    //将任意文本隐藏在音频视频图片和文本中的多种方式
- https://0xrick.github.io/lists/stego/    //隐写术工具集，Steganography - A list of useful tools and resources。包括隐写工具，解析工具
- https://github.com/DominicBreuker/stego-toolkit    //隐写工具包。Stegosuite
- https://github.com/livz/cloacked-pixel    //Py3。LSB图片数据隐藏
- http://www.caesum.com/handbook/Stegsolve.jar    //Java。图片隐写查看器，多图层查看器。
## 压力测试
- https://github.com/ywjt/Dshield    //Py。DDOS防护
- https://rocketstresser.com/login.php    //多协议，支持cdn测试
- https://klionsec.github.io/2017/11/15/hping3/    //HPing3网络工具组包
### 压力流量测试
- http://www.yykkll.com    //压测站评测。W:defconpro.net;W:vip-boot.xyz;--
- https://github.com/NewEraCracker/LOIC/    //C#。基于Praetox's LOIC project的压测工具，使用mono进行跨平台。
- https://github.com/EZLippi/WebBench    //C。DDOS网站压力测试，最高并发3万
- https://github.com/ajmwagar/lor-axe    //RUST。多线程、低带宽消耗的HTTP DoS工具
- https://github.com/IKende/Beetle.DT    //C#。分布式压力测试工具
- https://github.com/649/Memcrashed-DDoS-Exploit    //Py。利用shodan搜索Memcached服务器进行压力测试
- https://github.com/mschwager/dhcpwn    //Py。DHCP/IP压力测试
- https://github.com/Microsoft/Ethr    //Go。跨平台，TCP， UDP， HTTP， HTTPS压力测试工具
- https://github.com/Markus-Go/bonesi    //C。模拟僵尸网络进行ICMP/UDP/TCP/HTTP压测
### 压力拒绝服务
- https://github.com/jseidl/GoldenEye    //Py。DOS攻击测试
- https://github.com/jagracey/Regex-DoS    //RegEx拒绝服务扫描器
- https://github.com/algo7/bluekeep_CVE-2019-0708_poc_to_exploit    //Py。RDP服务远程命令执行/DOS攻击/蓝屏exp。
- https://xz.aliyun.com/t/7895/    //利用WAF进行拒绝服务攻击。利用自动加载图片等资源文件的特性。
- https://xz.aliyun.com/t/7895/    //利用WAF进行拒绝服务攻击
---
# wiki_TowerDefence
- https://github.com/euphrat1ca/security_w1k1/blob/master/wiki_TowerDefence.md/    //安全体系防御，病毒后门查杀，系统监控，昏晓命令检测。mywiki
# wiki_MalwareSec
- https://github.com/euphrat1ca/security_w1k1/blob/master/wiki_MalwareSec.md/    //病毒分析，应急响应合集。mywiki
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