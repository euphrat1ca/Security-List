***项目简介***
根据中华人民共和国《网络安全法》相关政策规定，本文章只做学习测试，不被允许通过本文章技术手段进行非法行为，使用技术的风险由您自行承担(The author does not assume any legal responsibility.)<br>
&emsp;&emsp;https://github.com/euphrat1ca/security_w1k1 //Have to say,the index is in my mind<br>
&emsp;&emsp;一个 Red Team 攻击的生命周期，整个生命周期包括：信息收集、攻击尝试获得权限、持久性控制、权限提升、网络信息收集、横向移动、数据分析（在这个基础上再做持久化控制）、在所有攻击结束之后清理并退出战场（扫尾）。<br>
&emsp;&emsp;几千行的项目有点过于庞大，于是在第两百次更新的时候，选择把一些较为频繁的持续更新内容分到其它文件内。<br>
分类标签：mywiki;intro;工具手册;通讯技术工具;威胁情报;恶意样本;自服务应用;研究技术;漏洞利用;Web安全;<br>
导航标签：一个人的安全部;Awesome系列;类似于*架构;<br>
类型标签：模拟测试;* Kali系统类;* ATT&CK矩阵类;作者拼音;Github:\Web:\Page:\Connect;常见缩写;<br>
状态标签：simple;noupdate;商业版;社区版;<br>
测评标签：testjob;welljob;goodjob;greatjob;<br>
# 安全相关资源列表
- https://arxiv.org    //康奈尔大学（Cornell University）开放文档
- https://github.com/sindresorhus/awesome    //awesome系列
- http://www.owasp.org.cn/owasp-project/owasp-things    //OWASP项目
- https://github.com/SecWiki/sec-chart    //安全思维导图集合
- https://github.com/Mayter/sec-charts    //在sec-wiki的思维导图 plus
- https://github.com/Ascotbe/Osmographic-brain-mapping    //安全思维脑图。ctf/web/二进制/ai/区块链/业务/主机/社工/移动/无线/运维/风控
- https://github.com/tom0li/collection-document    //安全部/攻防/内网/Web/apt/漏洞预警/开发/Bug Bounty/SDL/SRC
- https://github.com/secure-data-analysis-data-sharing/data-analysis 资料分为安全态势、攻防对抗、数据分析、威胁情报、应急响应、物联网安全、企业安全建设、其他书籍八部分
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
- https://github.com/JacksonBruce/AntiXssUF    //C#。跨站脚本攻击（XSS）过滤器，以白名单的过滤策略，支持多种过滤策略
- "网页安全政策"（Content Security Policy，缩写 CSP）防御xss，可以通过网页meta标签和http头。开启httponly；更换chrome；
- https://www.bbsmax.com/A/1O5EvMgyd7/    //CORS（跨域资源共享）的防御机制
- https://www.freebuf.com/articles/web/227694.html/    //垃圾邮件防御手段，通过SPF记录；DKIM数据签名进行；DMARC策略（基于SPF和DKIM协议的可扩展电子邮件认证协议）。关于钓鱼邮件的学习笔记
- https://zhuanlan.zhihu.com/p/43716885/    //使用knockd管理高危端口
### 红队基础设施自动化部署建设
- https://github.com/QAX-A-Team/LuWu    //Bash。红队基础设施自动化部署工具
- 公众号：红队攻防全流程解析    //
### 安全实验室中心建设
- https://www.freebuf.com/articles/es/211571.html    //安全实验室的发展及展望
- 公众号：开篇|猪八戒安全建设漫谈 安全体系建设分享01期|目标、团队、考核    //
- https://bbs.ichunqiu.com/thread-53927-1-1.html    //奇安信「实战攻防三部曲」要点总结。实战攻防之红蓝紫队
- https://github.com/Leezj9671/offensiveinterview    //安全/渗透测试/红队面试题.G:WebBreacher/offensiveinterview;
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
- https://snyk.io/    //无服务器，环境漏洞检测。SDL建设。G:snyk/snyk;
- https://mp.weixin.qq.com/s/STBzFf-NtfbDEA5s9RBdaw/    //秦波：大型互联网应用安全SDL体系建设实践
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
- https://github.com/chryzsh/DarthSidious    //从0开始你的域渗透之旅，包括搭建到渗透测试域环境。G:crazywa1ker/DarthSidious-Chinese;
- https://paper.seebug.org/913/    //如何打造自己的PoC框架-Pocsuite3-框架篇。simple
## 安全基础科普培训
- https://book.yunzhan365.com/umta/rtnp/mobile/index.html    //网络安全科普小册子
- https://book.yunzhan365.com/ybab/exnz/mobile/index.html    //FP50 优秀网络安全解决方案 白皮书
- http://sec.cuc.edu.cn/huangwei/textbook/ns/    //网络安全电子版教材。中传信安课程网站
- https://space.bilibili.com/37422870    //入门安全视频
- https://space.bilibili.com/406898187/channel/detail?cid=85655    //安全帮内网高级加固课程
- https://ilearningx.huawei.com/portal/#/portal/EBG/26    //华为e学云。安全科普
- https://github.com/tiancode/learn-hacking    //网络安全入门文章集
- https://keenlab.tencent.com/zh/index.html    //腾讯科恩实验室
- https://www.freebuf.com/articles/neopoints/190895.html    //入门介绍。fuzz/漏挖/脚本
- https://github.com/ym2011/SecurityManagement    //分享安全管理体系、ISO27001、等级保护、安全评审的经验
- https://null-byte.wonderhowto.com    //msf/fb/wifi/pass/取证/social/信息收集
- https://github.com/knownsec/RD_Checklist    //知道创宇技能列表
- https://github.com/ChrisLinn/greyhame-2017    //灰袍技能书2017版本
### 安全大会资料
- https://www.hackinn.com/search/?keyword=    //资料站。W:srxh1314.com/;W:infocon.org/;W:vipread.com/;--
- http://www.irongeek.com/i.php?page=security/hackingillustrated    //国内外安全大会相关视频与文档
- https://github.com/knownsec/KCon    //KCon大会文章PPT。P:blackhat黑帽大会;--
### 安全工具使用手册指导介绍
- https://github.com/HarmJ0y/CheatSheets    //多个项目的速查手册（Beacon / Cobalt Strike，PowerView，PowerUp，Empire和PowerSploit）
- https://www.cnblogs.com/backlion/p/10616308.html    //Coablt strike官方教程中文译版本
- https://github.com/aleenzz/Cobalt_Strike_wiki    //Cobalt Strike系列 教程使用
- https://wizardforcel.gitbooks.io/kali-linux-web-pentest-cookbook/content/    //Kali Linux Web渗透测试秘籍 中文版
- https://github.com/louchaooo/kali-tools-zh    //kali下工具使用介绍手册
- https://www.offensive-security.com/metasploit-unleashed/    //kali出的metasploit指导笔记
- http://www.hackingarticles.in/comprehensive-guide-on-hydra-a-brute-forcing-tool/ hydra使用手册
- https://www.gitbook.com/book/t0data/burpsuite/details    //burpsuite实战指南
- https://zhuanlan.zhihu.com/p/26618074    //Nmap扩展脚本使用方法
- https://github.com/hardenedlinux/linux-exploit-development-tutorial    //Linux exploit 开发入门
- https://wizardforcel.gitbooks.io/asani/content    //浅入浅出Android安全 中文版
- https://wizardforcel.gitbooks.io/lpad/content    //Android 渗透测试学习手册 中文版
### Offensive Security全家桶
- https://github.com/b1n4ry4rms/RedTeam-Pentest-Cheatsheets/    //常见工具命令
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
- https://github.com/aqzt/sso    //服务器安全运维规范（Server security operation）
- https://github.com/imthenachoman/How-To-Secure-A-Linux-Server    //Linux服务器保护。9k
- https://github.com/SwiftOnSecurity/sysmon-config    //sysmon配置文件安装
- https://github.com/trimstray/nginx-admins-handbook    //nginx操作手册。8k
- https://github.com/valentinxxx/nginxconfig.io/    //在线nginx配置文件生成，W:nginxconfig.io;--
- https://github.com/openspug/spug/    //JS,Py。轻量级无Agent的自动化运维平台，整合了主机管理、主机批量执行、主机在线终端、文件在线上传下载、应用发布部署、在线任务计划、配置中心、监控、报警等功能。
### 系统安全检查基线配置
- https://www.open-scap.org/    //安全基线评估工具集
- https://www.cisecurity.org/cis-benchmarks/    //CIS总结的140多种配置基准
- https://github.com/Jsitech/JShielder    //linux下服务器一键加固脚本
- https://github.com/trimstray/linux-hardening-checklist    //Linux服务器加固基线
- https://github.com/a13xp0p0v/kconfig-hardened-check    //用于检查 Linux 内核配置中的安全加固选项的脚本
- https://gist.github.com/mackwage/08604751462126599d7e52f233490efe    //Windows安全加固命令
- https://github.com/wstart/DB_BaseLine    //数据库基线检查工具
- https://github.com/drduh/macOS-Security-and-Privacy-Guide    //Py。MacOS安全性基线。
- https://github.com/re4lity/Benchmarks    //常用服务器、数据库、中间件安全配置基线 ，基本包括了所有的操作系统、数据库、中间件、网络设备、浏览器、安卓、IOS、云服务的安全配置。
### 安全服务checklist
- https://github.com/juliocesarfort/public-pentesting-reports    //由几家咨询公司和学术安全组织发布的公共渗透测试报告的列表。
- http://pentestmonkey.net/category/cheat-sheet    //渗透测试常见条目
- https://github.com/arunmagesh/hw_hacking_cheatsheet    硬件hardware测试条目
- https://mp.weixin.qq.com/s/O36e0gl4cs0ErQPsb5L68Q    //区块链，以太坊智能合约审计 CheckList
- https://github.com/slowmist/eos-bp-nodes-security-checklist    //区块链，EOS bp nodes security checklist（EOS超级节点安全执行指南）
- https://github.com/0xRadi/OWASP-Web-Checklist    //owasp网站检查条目
- https://github.com/GitGuardian/APISecurityBestPractices    //api接口测试checklist
- https://github.com/shieldfy/API-Security-Checklist    //api开发核对清单。12k。
- https://github.com/theLSA/CS-checklist    //CS客户端安全检查checklist
- https://xz.aliyun.com/t/2089    //金融科技SDL安全设计checklist
- 汽车安全测试Checklist    //水滴安全实验室
- https://blog.csdn.net/qq_39541626/article/details/104891590    //小程序、公众号安全测试list
- https://www.butian.net/School/content?id=307/    //移动通信网络渗透测试科普
## 应急响应溯源
- https://security.tencent.com/opensource/detail/19    //腾讯开源的xSRC应急响应中心cms
- https://www.secrss.com/articles/10986    //一次攻防实战演习复盘总结。奇安信
- https://github.com/Bypass007/Emergency-Response-Notes    //应急响应实战笔记。应急响应/日志分析/僵木蠕分析。2k。G:theLSA/emergency-response-checklist 应急响应指南;-
- https://github.com/tide-emergency/yingji    //Py3。查看主机状态/启动项/历史命令/用户特权/文件修改/异常IP等
- https://github.com/ppabc/cc_iptables    //收集处理DDOS、CC攻击各类脚本，包括NGINX日志中的CC攻击IP处理。
- https://github.com/al0ne/LinuxCheck    //Bash。linux信息收集/应急响应/常见后门检测脚本
### 日志分析可视化
- https://github.com/grafana/grafana    //TypeScript,Go。用于可视化大型测量数据的开源程序，提供创建、共享、浏览数据方法与众多功能插件。greatjob。29.5k。
- https://github.com/Cyb3rWard0g/HELK    //Jupyter Notebooks.基于ELK(Elasticsearch, Logstash, Kibana)的日志威胁分析。1.5K。
- https://github.com/JeffXue/web-log-parser    //Py。web日志分析工具
- https://github.com/JPCERTCC/LogonTracer    //JS,Py。根据win登陆记录日志来分析并用图形化展示恶意登陆行为
- https://github.com/jpcertcc/sysmonsearch    //JS。将Sysmon的日志结果可视化
- https://github.com/olafhartong/sysmon-cheatsheet    //Sysmon操作手册，各id属性含义
- https://github.com/baronpan/SysmonHunter    //JS。针对att&ck对sysmon日志进行分析展示
- https://github.com/zhanghaoyil/Hawk-I    //Py。基于无监督机器学习算法从Web日志中自动提取攻击Payload
- https://github.com/JPCERTCC/LogonTracer    //Py。日本计算机应急团队开源的关于Windows下登录日志的追踪溯源，网络信息格式化展示。Github:Releasel0ck/NetTracer;
- https://gitee.com/524831546/xlog/    //Go。web访问日志分析工具,可以分析nginx、resin ,tomcat,apache访问日志，然后对访问的ip，流量，响应时间，状态码，URI，浏览器，爬虫进行详细全面的分析展示。
### 勒索病毒
- https://github.com/jiansiting/Decryption-Tools    //勒索病毒解决方案汇总
- https://www.nomoreransom.org    //在线勒索病毒解决方案
## 攻防技术资源学习
- https://attack.mitre.org    //mitre科技机构对攻击技术的总结wiki，攻击矩阵模型。
- https://github.com/infosecn1nja/awesome-mitre-attack    //Mitre ATT&CK™框架资源收集。Web:huntingday.github.io;G:lengjibo/ATT-CK-CN //att&ck实操实验记录;W:vulhub.org.cn/attack //att&ck汉化;--
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
- https://www.imperva.com/blog/nosql-ssji-authentication-bypass/    //SSJI服务的JavaScript注入
### 学习内网安全后渗透
- https://attack.mitre.org/wiki/Lateral_Movement    //mitre机构对横向移动的总结
- https://github.com/l3m0n/pentest_study    //从零开始内网渗透学习。G:Ridter/Intranet_Penetration_Tips;-
- https://github.com/uknowsec/Active-Directory-Pentest-Notes    //个人域渗透学习笔记，配合域环境搭建。goodjob。
- https://klionsec.github.io/2016/08/10/ntlm-kerberos/    //深刻理解windows安全认证机制 [ntlm & Kerberos]。W:彻底理解Windows认证 - 议题解读;公众号：域渗透 | Kerberos攻击速查表;P:Kerberos的白银票据详解/Kerberos的黄金票据详解;
- https://daiker.gitbook.io/windows-protocol    //内网域基础协议分析系列文章。本系列文章将针对内网渗透的常见协议Windows凭证利用(如kerbeos,ntlm,smb,ldap等)进行协议分析，相关漏洞分析以及漏洞工具分析利用。
- https://github.com/infosecn1nja/AD-Attack-Defense    //AD活动目录攻击链与防御
- https://github.com/nccgroup    //国外安全咨询团队，burp插件的编写、内网利用工具、app安全工具
- https://adsecurity.org    //Active Directory安全攻防。goodjob。
- https://3gstudent.github.io    //AD域渗透/DNS/可信目录/横向移动。G:klionsec.github.io;--
- https://www.anquanke.com/post/id/87976    //Powershell攻击指南黑客后渗透之道系列——基础篇\进阶利用\实战篇
# 技术手段利用方式工具集合
- https://github.com/infosecn1nja/Red-Teaming-Toolkit    //红队攻击生命周期，开源和商业工具。goodjob。
- https://github.com/redcanaryco/atomic-red-team    //Atomic Red Team团队关于win、linux、mac等多方面apt利用手段、技术与工具集。2k。
- https://github.com/blaCCkHatHacEEkr/PENTESTING-BIBLE    //红队工具、攻击手段
- https://github.com/toolswatch/blackhat-arsenal-tools    //blackhat工具集
- https://github.com/demonsec666/Security-Toolkit    //渗透攻击链中常用工具及使用场景
- https://github.com/n00py/ReadingList/blob/master/gunsafe.txt    //安全工具集
- https://github.com/BlackDiverX/cqtools    //Windows利用工具集
- https://github.com/k8gege/    //K8工具合集(内网渗透/提权工具/远程溢出/漏洞利用/扫描工具/密码破解/免杀工具/Exploit/APT/0day/Shellcode/Payload/priviledge/BypassUAC/OverFlow/WebShell/PenTest) Web GetShell Exploit(Struts2/Zimbra/Weblogic/Tomcat/Apache/Jboss/DotNetNuke/zabbix)。P:cnblogs.com/k8gege，常见解压密码Kk8team\Kk8gege。
- https://www.parrotsec.org    //鹦鹉安全操作系统。pentest kali系统类。
- https://github.com/fireeye/commando-vm    //FireEye开源CommandoVM，专为红队（pen-testing）定制的Windows。W:blackwin.ir,WINDOWS kali系统类;--
- https://github.com/theLSA/hack-cs-tools    //CS客户端测试工具，配合客户端checklist
- https://github.com/kabachook/k8s-security/    //bash/py.Kubernetes安全集合
- https://github.com/microsoft/WindowsProtocolTestSuites    //C#。针对Windows开发规范的Windows协议测试套件
- https://github.com/ConsenSys/mythril-classic    //用于以太坊智能协议的安全分析工具
- https://github.com/lionsoul2014/ip2region    //ip地址定位库，支持python3等多接口。类似于于geoip架构
- https://github.com/ultrasecurity/webkiller    //Py。渗透辅助。ip信息、端口服务指纹、蜜罐探测、bypass cloudflare
- https://github.com/medbenali/CyberScan    //Py。渗透测试辅助工具。支持分析数据包、解码、端口扫描、IP地址分析等
- https://github.com/ismailtasdelen/hackertarget    //Py。Use open source tools and network intelligence to help organizations with attack surface discovery and identification of security vulnerabilities.
- https://technitium.com/    //点对点加密聊天、mac地址修改、dns客户端与服务端、https
- https://github.com/feross/SpoofMAC    //Py。跨平台mac修改
## 信息隐匿保护
- https://github.com/ffffffff0x/Digital-Privacy/    //一个关于数字隐私搜集、保护、清理集一体的方案,外加开源信息收集(OSINT)对抗。类wiki_OsintData；wiki_Selfsource；wiki_FreeConnect。goodjob。
- https://github.com/leitbogioro/Fuck_Aliyun    //关闭阿里云监控服务
- https://github.com/Nummer/Destroy-Windows-10-Spying    //DWS用来关闭windows监控服务
- https://github.com/JusticeRage/freedomfighting    //日志清理、文件共享、反向shell
- https://github.com/Rizer0/Log-killer    //日志清除，Windows/Linux 服务器中的所有
- https://github.com/360-A-Team/EventCleaner    //日志擦除工具
### 隐匿流量洋葱路由
- https://www.torproject.org/    //洋葱浏览器。P:dnmugu4755642434.onion/ kilos搜索引擎;
- https://github.com/s-rah/onionscan    //darkweb暗网爬虫
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
- https://github.com/klionsec/SuperWordlist/    //实战沉淀下的各种弱口令字典
- https://github.com/tarraschk/richelieu    //.fr邮箱密码表
- https://github.com/TheKingOfDuck/fuzzDicts/    //Web Pentesting Fuzz 字典。G:xmendez/wfuzz/tree/master/wordlist;G:We5ter/Scanners-Box;G:shack2/SNETCracker/dic;
- https://github.com/danielmiessler/SecLists    //用户名，密码，URL，敏感数据模式，模糊测试负载，Web shell。G:7dog7/bottleneckOsmosis;G:Ridter/Pentest;
- https://github.com/alpha1e0/pentestdb    //WEB渗透测试数据库。用于提供渗透测试的辅助工具(pentest-tool)、资源文件
- https://github.com/brannondorsey/PassGAN    //Py。深度学习，密码字典样本生成
- https://github.com/Mebus/cupp    //Py。根据用户习惯密码生成弱口令探测
- https://github.com/Saferman/cupper    //Py。根据用户习惯密码生成弱口令探测，楼上升级
- https://github.com/LandGrey/pydictor    //Py3。特定密码字典生成
- https://github.com/HongLuDianXue/BaiLu-SED-Tool    //pascal.白鹿社工字典生成器
- https://github.com/digininja/CeWL/    //Ruby。爬取目标网站关键词生成字典。testjob.
### 程序功能模块库
- https://github.com/Microsoft/SymCrypt    //Windows使用的核心功能加密库
- https://github.com/unknownv2/CoreHook    //C#。基于.NET Core运行时实现的Windows HOOK库
- https://github.com/boy-hack/hack-requests    //Py3。python包模块。burp数据包重放、线程安全、底层包日志分析
- https://github.com/saghul/aiodns/    //Py。请求后无需关闭连接的情况下有效地进行多次调用的DNS解析器
## 社工相关
- https://github.com/mehulj94/Radium-Keylogger    //py.键盘记录工具。
- https://github.com/ggerganov/kbd-audio    //C++。linux下利用麦克风监控键盘输入测试输入值。
- https://github.com/Pickfordmatt/SharpLocker/    //c#。Windows锁屏密码记录。G:bitsadmin/fakelogonscreen;PS:Invoke-LoginPrompt.ps1;PS:Invoke-CredentialsPhish.ps1;Koadic:password_box;Empire:collection/toasted;Empire:collection/prompt;MSF:phishwindowscredentials;--
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
- https://github.com/jbtronics/CrookedStyleSheets    //php.使用CSS实现网页追踪 / 分析，用户鼠标轨迹捕捉
### 邮件伪造
- https://emkei.cz    //在线邮件伪造。多功能模拟。W:tool.chacuo.net/mailanonymous;
W:ns4gov.000webhostapp.com;
- https://github.com/Macr0phag3/email_hack    //Py。钓鱼邮件伪造。G:lunarca/SimpleEmailSpoofer;G:Dionach/PhEmail;
- https://www.jetmore.org/john/code/swaks/    //Perl。基于smtp的邮箱域名伪造测试工具
### 口令扫描爆破证书校验
- https://github.com/vanhauser-thc/thc-hydra    //C。支持多种协议方式的破解与爆破.G:scu-igroup/ssh-scanner;G:lijiejie/htpwdScan;G:ztgrace/changeme;G:netxfly/crack_ssh;G:euphrat1ca/F-Scrack;--
- https://github.com/maaaaz/thc-hydra-windows    //C。hydra的windows编译版本.
- https://github.com/shack2/SNETCracker    //C#。密码爆破工具，支持SSH、RDP、MySQL等常见协议,超级弱口令爆破工具.
- https://github.com/jmk-foofus/medusa    //C。快速并发模块化的登陆爆破工具。
- https://github.com/lanjelot/patator    //Py3。集成Hydra, Medusa, Ncrack, Metasploit modules and Nmap NSE验证爆破工具。
- https://github.com/nmap/ncrack    //C。Nmap协议破解爆破组件.
- https://github.com/galkan/crowbar    //Py。支持openvpn、rdp、ssh、vnc破解.G:shengqi158/weak_password_detect;--
- https://github.com/ShawnDEvans/smbmap    //py.利用smb服务传递哈希、增删改查、命令执行、ip段共享枚举等。G:m4ll0k/SMBrute;--
- https://github.com/InfosecMatter/Minimalistic-offensive-security-tools    //ps。smb、ad域密码爆破。
- https://github.com/3gstudent/SharpRDPCheck    //C#。RDP爆破验证，支持ntlm登录验证。G:najachai/RDPUploader;--
- https://github.com/euphrat1ca/Fast-RDP-Brute-GUI-v2.0-by_Stas-M--Official/    //RDP密码爆破、扫描，Fast RDP Brute GUI by Stas M，stascorp.com解压密码Stas'M Corp.
- https://github.com/TunisianEagles/SocialBox    //针对fb、gmail、ins、twitter的用户名密码爆破的脚本.
- https://github.com/Moham3dRiahi/XBruteForcer    //perl.WordPress、Joomla、DruPal、OpenCart、Magento等CMS爆破.
### 密码破解哈希还原
- https://ophcrack.sourceforge.io/    //C。使用彩虹表Rainbow table来破解视窗操作系统下的LAN Manager散列（LM hash）的计算机程序。xp、vista
- https://securityxploded.com/download.php/    //各种密码方向安全小工具
- https://github.com/bdutro/ibm_pw_clear    //IBM x3550/x3560 M3 bios密码清除重置工具
- https://github.com/hashcat/hashcat    //C。哈希破解
- https://github.com/fireeye/gocrack    //Go。基于hashcat 3.6.0+的分布式密码破解工具
- https://github.com/s3inlc/hashtopolis    //php.hashcat的分布式破解工具，支持C#与python客户端
- https://github.com/chris408/known_hosts-hashcat    //Py。利用hashcat破解ssh密码hash
- https://github.com/clr2of8/DPAT    //Py。利用hashcat等工具域密码进行破解测试
- https://github.com/testsecer/Md5Decrypt    //C#。md5多接口查询基于网上web API的MD5搜索工具
- https://github.com/s0md3v/Hash-Buster    //能调用多个API进行hash破解查询的智能工具
- https://github.com/magnumripper/JohnTheRipper    //C。开膛手john，已知密文的情况下尝试破解出明文的破解密码软件
- https://github.com/shinnok/johnny    //C++。JohnTheRipper密码破解的GUI界面，理论兼容所有功能，有windows界面
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
## 资产信息搜集
- https://github.com/zmap/zmap    //C。无状态扫描，可使用C编写扩展模块。censys三件套。
- https://github.com/zmap/zgrab2    //Go。配合zmap/ztag的指纹抓取工具。censys三件套。G:chichou/grab.js;--
- https://github.com/zmap/zdns    //Go。Fast CLI DNS Lookup Tool。censys三件套。
- https://github.com/zmap/ztag    //Py。对zmap\zgrab产生的数据分析打标签。censys三件套。
- https://github.com/xiaoheiwo/GGSCAN    //py。联动nmap、masscan、hydra的快速资产探测工具。G:sowish/LNScan;G:dr0op/bufferfly;--
- https://github.com/ywolf/F-NAScan    //Py3。网络资产、端口服务搜集整理，生成报表显示。G:flipkart-incubator/RTA;--
- https://github.com/grayddq/PubilcAssetInfo    //Py3。主要目标是以甲方安全人员的视角，尽可能收集发现企业的域名和服务器公网IP资产，如百度云、阿里云、腾讯云等。一个人的安全部。
- https://github.com/cea-sec/ivre    //Py。网络资产指纹发现，bro/argus/nfdump/p0f/nmap/zmap/masscan/数据库mongoDB。Github:Scan-T;G:LangziFun/LangNetworkTopology3;--
- https://github.com/nray-scanner/nray    //Go。分布式扫描工具，支持ldap\证书扫描。
### 资产端口扫描
- https://github.com/nmap/nmap    //Lua。Nmap扫描器具有有强大的脚本引擎框架。greatjob。
- https://github.com/robertdavidgraham/masscan    //C。无状态扫描器。10k。On Windows, or from VMs, it can do 300,000 packets/second. On Linux (no virtualization) it'll do 1.6 million packets-per-second。
- https://paper.seebug.org/1052/    //Intro。从 Masscan, Zmap 源码分析到开发实践。扫描方式socket/libpcap/PF_RING DNA设备/ 三种介绍
- https://github.com/OffensivePython/Nscan    //Py。类Masscan和Zmap架构
- https://github.com/angryip/ipscan    //Java。Angry IP Scanner。跨平台界面化端口扫描器,angryip.org。
- http://www.advanced-ip-scanner.com    //Advanced IP Scanner Portable端口扫描器。商业版。
- https://github.com/RASSec/RASscan    //Py。基础端口服务扫描demo。
- https://github.com/tengzhangchao/PortScan    //Py,Go。基础端口扫描器demo，simple。
### 资产信息收集
- https://github.com/cedowens/SwiftBelt/    //Swift。macOSX系统信息搜集
- https://github.com/GhostPack    //C#。SpecterOps公司关于PowerShell 功能的各种 C# 实现的集合，包括信息搜集\权限提升\密钥窃取等
- https://github.com/m8r0wn/nullinux    //Py。用于Linux的内部渗透测试工具，可用于通过SMB枚举操作系统信息，域信息，共享，目录和用户。
- https://github.com/BloodHoundAD/BloodHound    //PS。使用图论进行内网信息域内关系与细节整理，作为DEFCON 24的免费开源工具发布。通过脚本导出域内的session、computer、group、user等信息，入库后进行可视化分析域成员和用用户关系。testjob,3k。
- https://www.4hou.com/penetration/5752.html    //Intro。域渗透提权分析工具 BloodHound 1.3 中的ACL攻击路线。
- https://github.com/fdiskyou/hunter    //C++。调用 Windows API 对内网信息搜集。testjob。
- https://github.com/scallywag/nbtscan    //C。NetBIOS协议主机设备发现。NetBScanner、nmap、msf都有此功能，这个比较轻。
- https://github.com/royhills/arp-scan    //C。ARP协议主机设备发现。
### 资产风险测试
- https://github.com/ysrc/xunfeng    //Py。巡风采用web界面，由同程安全开发的网络资产管理、漏洞检测引擎。goodjob。2k。G:ody5sey/Voyager;G:CTF-MissFeng/bayonet;--
- https://gobies.org/    //goby是白帽汇资产风险管理工具。端口、服务、截图、弱口令测试。goodjob。W:rumble.run;G:grayddq/PublicMonitors;--
- https://github.com/w-digital-scanner/w12scan    //py3。django + elasticsearch + redis(去重+web与w12scan-client通信中间件)网络资产发现引擎，通过WEB API下发任务。boy-hack开发。
- https://github.com/jeffzh3ng/Fuxi-Scanner    //Py。资产收集，漏洞检测（集成awvs、创宇Pocsuite、nmap、hydra）。
- https://github.com/TideSec/Mars    //Py。基于docker资产安全检测（集成awvs、创宇Pocsuite、nmap、hydra），一键启动。G:0xbug/Biu-framework;--
- https://github.com/lcatro/network_backdoor_scanner    //C++。反向链接、内外网穿透、通信数据加密，http弱口令破解。
- https://github.com/vletoux/pingcastle   //Py。AD域信息威胁等级测试
- https://github.com/mitre/caldera    //mitre公司apt攻击模拟测试，主要针对win。G:NextronSystems/APTSimulator;--
- https://github.com/guardicore/monkey    //Py。C2架构，利用默认口令、exp、多种协议（wmi组件、ssh、smb等）方式进行攻击检测，恶意病毒传播模拟测试。P:guardicore.com/infectionmonkey;G:lawrenceamer/0xsp-Mongoose;--
- https://github.com/zhaoweiho/SecurityManageFramwork    //PY3。SecurityManageFramwork-SeMF基于django2，包含资产管理，漏洞管理，账号管理，知识库管、安全扫描自动化功能模块，可用于企业内部的安全管理。goodjob。
- https://github.com/alphasoc/flightsim    //Golang。malicious恶意网路流量模拟测试.
### 资产漏洞生命周期
- https://github.com/infobyte/faraday    //协作渗透测试和漏洞管理平台
- https://github.com/DefectDojo/django-DefectDojo    //Py。基于django的漏洞资产管理平台
- https://github.com/creditease-sec/insight    //web界面。宜信安全部开发，集成应用系统资产管理、漏洞全生命周期管理、安全知识库管理三位一体的管理平台
- https://github.com/RASSec/A_Scan_Framework    //漏洞管理、资产管理、任务扫描系统
## MITM攻击流量劫持
- https://github.com/bettercap/bettercap    //Go。中间人欺骗，网络攻击以及监控的瑞士军刀。该工具支持多种模块，比如中间人钓鱼框架、ARP/DNS欺骗、TCP以及数据包代理等。5K。GREATJOB。
- https://github.com/Binject/backdoorfactory    //Go。bettercap的二次开发拓展，用于将shellcode插入到网络上所有类型的二进制文件中。G:secretsquirrel/the-backdoor-factory;--
- https://github.com/mitmproxy/mitmproxy    //Py。中间人攻击，支持SSL拦截，进行https流量代理。greatjob。15k。
- https://github.com/qiyeboy/BaseProxy    //Py3。异步http/https代理，楼上简化版。可以作为中间人工具，比如说替换网址图片等
- https://github.com/LionSec/xerosploit    //中间人攻击测试工具包
- https://github.com/infobyte/evilgrade    //一个模块化的脚本框架，使攻击者在不知情的情况下将恶意更新注入到用户更新中
- https://github.com/AlsidOfficial/WSUSpendu    //可以自主创建恶意更新，并将其注入到WSUS服务器数据库中，然后随意的分发这些恶意更新
- https://github.com/quickbreach/smbetray    //专注于通过文件内容交换、lnk交换来攻击客户端，以及窃取任何以明文形式传输的数据
- https://github.com/mrexodia/haxxmap    //对IMAP服务器进行中间人攻击
- https://github.com/SySS-Research/Seth    //PY3/BASH。Linux下MitM RDP远程服务中间人攻击。G:citronneur/rdpy rdp远程服务模拟开启
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
## 移动安全
- https://github.com/Brucetg/App_Security    //App安全学习资源
- https://github.com/mirfansulaiman/Command-Mobile-Penetration-Testing-Cheatsheet    //移动安全测试条例
- https://github.com/OWASP/owasp-mstg    OWASP Mobile Security Testing Guide移动安全测试资源
- https://github.com/MobSF/Mobile-Security-Framework-MobSF    //软件自动化审计框架，支持docker运行。android、ios、win
- https://github.com/m0bilesecurity/RMS-Runtime-Mobile-Security/    //Py。Runtime Mobile Security (RMS) 移动端动态测试
- https://github.com/mwrlabs/drozer    //Py。MWR Labs开源Android 安全测试框架，支持编写自定义模块。
- https://github.com/nccgroup/house    //JS,Py。运行时手机 App 分析工具包， 带Web GUI
### 移动端渗透测试框架
- https://github.com/nettitude/scrounger    //Py。Linux下iOS和Android移动应用程序渗透测试框架
- https://gitlab.com/kalilinux/nethunter/build-scripts/kali-nethunter-project    //移动端KaliHunter手机渗透测试系统
- https://github.com/cSploit/android    //Java。cSploit: Android network pentesting suite手机渗透工具框架，可兼容msf
- https://github.com/euphrat1ca/Smartphone-Pentest-Framework    //PY/C/C++。SPF移动端渗透测试框架，支持电话通讯协议SS7漏洞利用，进行远程SS7指令操作。Web:shevirah.com/dagah/;
- https://github.com/metachar/PhoneSploit    //Py。通过shodan搜索开启调试模式的安卓设备，利用Adb控制安卓设备。
- https://termux.com/    //Termux是一个Android下一个高级的终端模拟器,开源且不需要root,支持apt管理软件包。
- https://github.com/Gameye98/Lazymux    //Py3。通过Termux打造免root安卓渗透工具
### Android/Java安全
- https://github.com/frida/frida/    //PY\Java。Frida是一款通过JavaScript代码注入应用程序的跨平台hook框架，二进制逆向动态调试。testjob。Github:dweinstein/awesome-frida;G:andreafioraldi/frida-fuzzer;--
- https://github.com/sensepost/objection    //Py。移动端动态调试安全检测，Frida公司开发。testjob。
- https://github.com/hanbinglengyue/FART/    //py.基于frida的ART环境下自动化脱壳方案。
- https://github.com/hluwa/ZenTracer    //Py。frida插件，Android方法调用追踪
- https://github.com/lyxhh/lxhToolHTTPDecrypt    //js.基于frida/Burp/flask的app渗透测试，利用HTTP协议，识别app加密算法，解密数据包，调用Burp。testjob.
- https://github.com/rovo89/Xposed    //C++。Android动态修改hook，隐藏root执行权限。
- https://github.com/Fuzion24/JustTrustMe    //Java。基于xposed模块进行app证书SSL注入抓包。
- https://taichi.cool/    //Android魔改框架太极，可加载 Xposed 模块、修改系统和APP、拦截方法，执行 hook 逻辑等，支持免root与Magisk模式。greatjob。社区版。
- https://github.com/android-hacker/VirtualXposed    //Java。基于VirtualApp 和 epic 免root使用xposed。greatjob。商业版。G:asLody/VirtualApp;
- https://github.com/Genymobile/scrcpy    //C。基于adb连接使pc控制Android设备
- https://github.com/zsdlove/ApkVulCheck    //Py3。对安卓apk进行特征值匹配。welljob。
- https://github.com/jboss-javassist/javassist    //Java。能够操作字节码框架，轻易的修改class代码文件。2.2K
- https://github.com/programa-stic    //基于Androguard 及Static Android Analysis Framework 的Android App静态分析引擎。
- https://github.com/WooyunDota/DroidSSLUnpinning    //安卓证书锁定解除的工具
- https://github.com/crifan/android_app_security_crack    //安卓应用的安全和破解。goodjob。
### IOS/macOS安全
- https://github.com/pwn20wndstuff/Undecimus/    //iOS 11.0 - 12.4全版本越狱。
- https://github.com/axi0mX/ipwndfu    //Py。checkm8利用ios底层全版本越狱
- https://github.com/dmayer/idb    //Ruby。开源的iOS App安全评估工具，作者是Danl A.Mayer。
- https://github.com/mwrlabs/needle    //Py。MWR Labs开发的一个开源iOS安全测试框架，同样支持开发自定义模块来扩展Needle的功能，目前主要功能包含对iOS应用数据存储，IPC。网络通信，静态代码分析，hooking及二进制文件防护等方面的安全审计。
- https://github.com/GeoSn0w/OsirisJailbreak12    //IOS12不完全越狱
- https://github.com/chaitin/passionfruit    //iOS应用逆向与分析工具，可以大大加速iOS应用安全分析过程
- https://sukarodo.me/gr00t/    //IOS12全版本越狱工具
- https://github.com/samyk/frisky    //针对 ios/mac OSX 应用的嗅探/修改/逆向/注入等工具
- https://github.com/LinusHenze/Keysteal    //C++。窃取MacOS下KeyChain。CVE-2019-8526
- https://github.com/coffeehb/Some-PoC-oR-ExP/blob/master/check_icmp_dos.py    //CVE-2018-4407，macos/ios缓冲区溢出可导致系统崩溃
- https://github.com/sickcodes/Docker-OSX    //OSX-KVM in Docker! X11 Forwarding!，基于qemu和kvm封装的苹果镜像docker。
## CTF相关(Capture The Flag)
- https://ctftime.org    //CTF排名比赛介绍
- https://ctf-wiki.github.io/ctf-wiki/    //CTFwiki，Misc/Crypto/Web/Assembly/Executable/Reverse/Pwn/Android/ICS
- https://firmianay.gitbooks.io/ctf-all-in-one    //CTF-All-In-One 《CTF 竞赛入门指南》。西电信安协会
- https://www.butian.net/School    //补天培训。CTF/攻防/硬件/社工/开发/代码审计。goodjob。G:imsebao/Code-Audit 代码审计;--
- https://github.com/adon90/pentest_compilation    //ctf比赛与OSCP考试中常见的知识点和命令
- https://github.com/Hacker0x01/hacker101    //Ruby。hacker one联名的Web攻防教学，有ctf靶场和视频.10K
- https://github.com/balsn/ctf_writeup    //CTF writeups from Balsn
- https://github.com/susers/Writeups  //国内玩各大CTF赛题及writeup整理。Github:hongriSec/CTF-Training;Github:balsn/ctf_writeup;
- https://edwardchoijc.github.io/CTF线下AWD经验总结.html/    //CTF攻防AWD经验总结
- https://github.com/NEALWE/AWD_FrameWork    //Py3。awd框架，比赛常用脚本。
- 公众号：VulnHub通关日记-DC_    //vulnhub write up
### CTF靶场平台
- https://github.com/facebook/fbctf    //HACK,PHP。CTF比赛平台搭建。
- https://github.com/CTFd/CTFd    //py2.基于flask的动态Capture The Flag framework
- https://github.com/zhl2008/awd-platform    //AWD攻防比赛平台。
- https://github.com/wuhan005/Asteroid/    //C#。CTF AWD 实时 3D 攻击大屏
- https://github.com/vidar-team/Cardinal/    //Go。CTF⛳️ AWD (Attack with Defense) 线下赛平台
- https://github.com/gabemarshall/microctfs    //SHELL,JS。小型ctf镜像docker
- https://github.com/giantbranch/pwn_deploy_chroot    //Py。部署多个pwn题到一个docker容器中
- https://github.com/PELock/CrackMeZ3S-CTF-CrackMe-Tutorial    //C++。为CTF比赛编写CrackMe软件
### CTF隐写术
- https://www.freebuf.com/sectool/208781.html    //将任意文本隐藏在音频视频图片和文本中的多种方式
- https://0xrick.github.io/lists/stego/    //隐写术工具集，Steganography - A list of useful tools and resources。包括隐写工具，解析工具
- https://github.com/DominicBreuker/stego-toolkit    //隐写工具包。Stegosuite
- https://github.com/livz/cloacked-pixel    //Py3。LSB图片数据隐藏
- http://www.caesum.com/handbook/Stegsolve.jar    //Java。图片隐写查看器，多图层查看器
### 二进制pwn利用CTF
- https://github.com/Gallopsled/pwntools    //Py。pwn类型，二进制利用框架
- https://github.com/ChrisTheCoolHut/Zeratool    //Py。pwn类型，二进制利用框架
- https://github.com/ChrisTheCoolHut/Rocket-Shot    //Py。pwn，自动攻击脚本
## 系统监控管理
- http://www.xuetr.com/    //PC Hunter是一个驱动级的系统维护工具，能够查看各种Windows的各类底层系统信息，包括进程、驱动模块、内核、内核钩子、应用层钩子，网络、注册表、文件、启动项、系统杂项、电脑体检等。pchunter
- down4.huorong.cn/hrsword.exe    //火绒剑系统管理。W:process monitor;--
- https://github.com/mohuihui/antispy    //C/C++。枚举32位系统中隐藏至深的进程、文件、网络连接、内核对象等，并且也可以检测用户态、内核态各种钩子
- https://github.com/draios/sysdig    //C++。系统活动监控，捕获和分析应用程序。它具有强大的过滤语言和可自定义的输出，以及可以使用称为chisels 的Lua脚本扩展的核心功能，sysdig.com。goodjob。6k。
- https://github.com/kkamagui/shadow-box-for-arm    //C/Py。ARM架构Linux系统监控，同仓库还有*shadow-box-for-x86*架构系统监控
- https://github.com/osquery/osquery    //C++。Facebook创建的SQL驱动操作系统检测和分析工具，支持像SQL语句一样查询系统的各项指标，如运行进程/加载内核模块/网络连接/浏览器插件/硬件事件/文件哈希等，osquery.io。14k。
- https://www.crystalidea.com/uninstall-tool    //Windows卸载，软件安装跟踪。P:CCleaner;
- http://emptyloop.com/unlocker/    //右键扩充工具，通过删除文件和程序关联的方式解除文件的占用。在解除占用时不会强制关闭占用文件进程
### 程序调试进程管理
- https://www.cheatengine.org    //CE（Cheat Engine）是一款内存修改编辑工具，程序函数监控，配合Ultimap功能食用更佳
- http://www.angusj.com/resourcehacker    //Windows二进制文件浏览编辑 (*.exe; *.dll; *.scr; etc) 和资源文件修改 (*.res, *.mui)图标属性等。Resource Hacker类似于于Restorator文件资源修改软件。
- https://github.com/euphrat1ca/PeDoll    //C++。基于inlineHook技术的软件分析工具，C/S架构
- https://github.com/everdox/InfinityHook    //C++。挂钩系统调用，上下文切换，页面错误等。
### 系统日志相关
- http://www.nirsoft.net/utils/computer_activity_view.html    //LastActivityView是一款电脑操作记录查看器，直接调用系统日志，显示安装软件、系统启动、关机、网络连接、执行exe 的发生时间和路径
- https://github.com/SwiftOnSecurity/sysmon-config    //Sysmon配置文件。系统进程监控，dns查询。
### 系统注册表监控
- https://sourceforge.net/projects/regshot/    //Regshot是注册表比较工具，通过抓取两次注册表快速比较得出两次注册表的不同之处
### 系统进程
- https://bitsum.com/    系统优化工具，主要功能是基于其特别的算法动态调整各个进程优先级以实现为系统减负的目的，可以用来监视进程动作
- https://www.portablesoft.org/    //可以Unlock占用文件的进程，查看文件或文件夹被占用的情况，内核模块和驱动的查看管理，进程模块的内存dump等工具
- https://github.com/open-falcon    //GO/Py。Falco是一款由Sysdig开源的进程异常行为检测工具。它既能够检测传统主机上的应用程序，也能够检测容器环境和云平台（主要是Kubernetes和Mesos）。Github:falcosecurity/falco;
- https://github.com/processhacker/processhacker    //C。监控系统资源、内存以及模块信息、软件调试，管理进程
- https://github.com/DominicBreuker/pspy    //Go。Linux非root权限，系统进程命令运行监控.GOODJOB.
- https://github.com/rabbitstack/fibratus    //Py。对Windows内核活动-进程/线程创建和终止，上下文转换，文件系统I/O，寄存器，网络活动以及DLL加载/卸载等进行捕捉。
### 系统文件监控
- https://www.zynamics.com/software.html    //BinDiff发现反汇编代码中的差异和相似之处。支持x86、MIPS、ARM/AArch64、PowerPC等架构进行二进制文件对比
- http://www.beyondcompare.cc/xiazai.html    //Beyond Compare是Scooter Software推出的文件比较工具。主要用于比较两个文件夹或者文件并将差异以颜色标记，比较的范围包括目录，文档内容等
- https://github.com/target/strelka    //Py3。文件变化实时监控。
# 安全体系防护相关
- https://github.com/Bypass007/Safety-Project-Collection    //收集一些比较优秀的开源安全项目，以帮助甲方安全从业人员构建企业安全能力。welljob。
- https://github.com/baidu/AdvBox    //Advbox是支持多种深度学习平台的AI模型安全工具箱，既支持白盒和黑盒算法生成对抗样本，衡量AI模型鲁棒性，也支持常见的防御算法
- https://github.com/quoscient/octopus    //区块链智能合约安全分析工具
- https://github.com/trimstray/otseca    //linux系统审计工具，可以导出系统配置，生成报表
- https://github.com/mwrlabs/dref    //DNS 重绑定利用框架
- https://github.com/chengr28/Pcap_DNSProxy/blob/master/README.zh-Hans.md    //Pcap_DNSProxy 是一个基于 WinPcap/LibPcap 用于过滤 DNS 投毒污染的工具
- https://github.com/PlagueScanner/PlagueScanner    //python.集成ClamAV、ESET、Bitdefender的反病毒引擎
- https://github.com/m4rco-/dorothy2    //一款木马、僵尸网络分析框架
- https://github.com/jumpserver/jumpserver    //Python3.开源堡垒机
- https://github.com/github/glb-director    //负载均衡组件GLB，数据解析使用了dpdk
- https://github.com/TKCERT/mail-security-tester    //检测邮件防护与过滤系统的测试框架
- https://github.com/chaitin/sqlchop-http-proxy    //利用HTTP 反向代理，内置 SQLChop 作为 SQL 注入攻击检测模块，可以拦截 SQL 注入流量而放行正常流量
- https://github.com/OWASP/SecureTea-Project    //当有人私自触碰电脑鼠标或触摸板，进行报警
- https://github.com/openitsystem/itops    //PY3/DJANGo。AD\Exchange管理系统
- https://github.com/tmobile/pacbot    //Java。云平台自动化安全监控工具
- https://github.com/mydlp    //MyDLP是一种简单，简单和开放的DLP（数据丢失预防）解决方案
- https://www.alienvault.com/products/ossim    //开源开源信息安全管理系统siem安全运维平台解决方案，支持snort\nmap等多种工具插件
## 安全防护建设
- https://github.com/trimstray/iptables-essentials    //IP table常见防火墙规则与命令。P:Firewall App Blocker 1.7 Windows防火墙快捷操作工具;P:Linux下防火墙 firewall-cmd;--
- https://github.com/SELinuxProject/selinux/    //C。安全增强型Linux（Security-Enhanced Linux），通过配置增强主机防护安全防御。
## 入侵检测感知防护
- http://m.imooc.com/article/21236    //快速自检电脑是否被黑客入侵过(Windows版)
- http://www.freebuf.com/articles/system/157597.html    //快速自检电脑是否被黑客入侵过（Linux版）
- http://www.freebuf.com/rookie/179638.html    //服务器入侵溯源小技巧整理
- https://bithack.io/forum/161    //Intro。如何通过一封恶意邮件追踪幕后黑客组织。邮件掉鱼、溯源、攻击者落地
- https://github.com/chaitin/yanshi    //C++。长亭偃师（yanshi），雷池（SafeLine）防火墙核心引擎使用到的代码生成工具，规则自动生成判断器械
- https://github.com/0Kee-Team/WatchAD    //Py。360 信息安全中心 0kee Team 域安全入侵感知系统，能够及时准确发现高级域渗透活动，检测覆盖内网攻击杀伤链大部分手法。
- https://github.com/Neo23x0/Loki    //一款APT入侵痕迹扫描器
- https://github.com/ossec/ossec-hids    //C。开源hids（主机入侵检测）堡垒
### EDR终端主机防护
- http://edr.sangfor.com.cn/    //深信服。SfAntiBotPro内存检索工具，可以根据输入的字符串快速检索计算机内存，输出包含该字符串的进程信息，在进行恶意域名检测时有事半功倍的效果
- http://edr.topsec.com.cn/    //天融信终端威胁防御系统
- https://github.com/felixweyne/ProcessSpawnControl    //PS。对恶意程序进行检测与监控
### NSM网络安全监控/入侵检测
- https://github.com/baidu/openrasp    //基于RASP。Runtime Application Self-Protection，实时应用自我保护，智能针对每个语言定制。G:baidu-security/openrasp-iast //灰盒扫描工具;testjob,1k。
- https://github.com/Security-Onion-Solutions/security-onion    //Security Onion洋葱安全入侵检测系统。基于Ubuntu，涵盖ELK\Snort\Suricata\Bro等组件，系统作为传感器分布在网络中监控多个VLAN和子网。hids kali系统类。
- https://github.com/snort3/snort3    //C++。snort知名NIDS网络入侵检测
- https://github.com/ptresearch/AttackDetection    //更新中的snort规则rules
- https://github.com/OISF/suricata    //C。IDS\IPS\NSM安全工具，兼容Snort插件
- https://github.com/iqiyi/qnsm    //C/C++。爱奇艺基于dpdk与Suricata，旁路部署的全流量引擎，集成了DDOS检测和IDPS模块。
- https://labs.360.cn/malwaredefender/    //HIPS (主机入侵防御系统)软件，用户可以自己编写规则来防范病毒、木马的侵害。另外，Malware Defender提供了很多有效的工具来检测和删除已经安装在您的计算机系统中的恶意软件
- https://documentation.wazuh.com    //C。wazuh是C/S架构开源主机入侵检测系统网络安全平台，支持日志收集、文件监控、恶意软件检测、漏洞基线检测等。
- https://github.com/TheKingOfDuck/FileMonitor    //py.基于watchdog的文件监视器变化监控（代码审计辅助）。testjob。
- https://github.com/StamusNetworks/SELKS    //基于Debian的入侵检测系统，组件包含Suricata IDPS与ELK和Scirius
- https://github.com/grayddq/HIDS    //主机型入侵检测系统。一个人的安全部
- https://github.com/ysrc/yulong-hids    //YSRC开源的驭龙HIDS主机入侵检测系统
- https://github.com/EBWi11/AgentSmith-HIDS    //c.Linux下基于Hook system_call的内核级HIDS，特点从内核态获取尽可能全的数据。welljob。
### 无线网络入侵检测
- https://github.com/anwi-wips/anwi    //无线IDS， 基于低成本的Wi-Fi模块(ESP8266)
- https://github.com/SYWorks/waidps    //Py。Linux下无线网络入侵检测工具
### 防火墙/waf/网关规则
- https://github.com/0xInfection/Awesome-WAF    //awesome waf
- http://www.safedog.cn/    //安全狗web防火墙。商业版。
- http://d99net.net/    //D盾防火墙，包含waf与webshel检测功能。商业版。P:xoslab.com 内核级检测文件生成写入;
- https://www.pfsense.org    //PHP。可配置snort规则的防火墙。社区版。
- https://github.com/evilsocket/opensnitch    //PY/Go。基于QT界面Linux下的应用防火墙
- https://github.com/SpiderLabs/ModSecurity    //C。跨平台 WAF engine for Apache/IIS/Nginx等
- https://github.com/klaubert/waf-fle    //ModSecurity Web控制台
- https://github.com/SpiderLabs/owasp-modsecurity-crs    //GO/C。owasp关于ModSecurity等防火墙规则库
- https://github.com/xsec-lab/x-waf    //适用于中小企业的云waf
- https://github.com/jx-sec/jxwaf    //Lua。JXWAF(锦衣盾)是一款基于openresty(nginx+lua)开发的web应用防火墙，独创的业务安全防护引擎和机器学习引擎可以有效对业务安全风险进行防护，解决传统WAF无法对业务安全进行防护的痛点。Github:starjun/openstar;Github:xsec-lab/x-waf;Github:loveshell/ngx_lua_waf;Github:starjun/openstar;
- https://github.com/Janusec/janusec    //Golang。应用安全网关，具备WAF、CC攻击防御、证书私钥加密、负载均衡、统一Web化管理等功能。G:w2sft/ShareWAF_Blance //WAF负载均衡;--
- https://github.com/qq4108863/himqtt/    //C。物联网epoll高并发防火墙
- https://github.com/koangel/grapeSQLI    //go.基于libinjection的Sql inject & XSS分析程序。
## Bypass安全防护绕过
- https://github.com/AMOSSYS/Fragscapy    //Py。防火墙fuzz绕过bypass
- https://github.com/kirillwow/ids_bypass    //IDS Bypass 脚本
- https://github.com/milo2012/ipv4bypass    //利用ipV6地址绕过waf
- https://github.com/3xp10it/bypass_waf    //防火墙绕过脚本
- https://github.com/swisskyrepo/PayloadsAllTheThings    //A list of useful payloads and bypass for Web Application Security and Pentest/CTF
- https://github.com/sirpsycho/firecall    //直接向CiscoASA防火墙发送命令， 无需登录防火墙后再做修改
- https://blog.xpnsec.com/evading-sysmon-dns-monitoring/    //Intro。规避Sysmon DNS监控
- https://mp.weixin.qq.com/s/QJeW7K-KThYHggWtJ-Fh3w    //网络层绕过IDS/IPS的一些探索。分片传输，ipv6进行ids/ips绕过
- https://github.com/al0ne/Nmap_Bypass_IDS    //Nmap&Zmap特征识别，绕过IDS探测
### 大数据平台安全
- https://github.com/shouc/BDA    //针对hadoop/spark/mysql等大数据平台的审计与检测
- https://github.com/wavestone-cdt/hadoop-attack-library    //hadoop测试方式和工具集
## 代码审计应用测试
- https://www.joinfortify.com    //HP出品的源代码安全审计工具Fortify SCA通过将其它语言转换成一种中间媒体文件NST（Normal Syntax Trcc），将源代码之间的调用关系、执行环境、上下文等分析清楚。通过匹配所有规则库中的漏洞。商业版。goodjob。
- https://www.checkmarx.com/    //源代码安全检测解决方案，动静态代码分析。商业版。
- https://securitylab.github.com/tools/codeql    //GitHub开源代码审计，插件、函数库形式
- https://github.com/microsoft/ApplicationInspector    //C#。基于规则代码安全审计
- https://github.com/pumasecurity/puma-scan    //C#。Visual Studio插件，实时代码审计
- https://github.com/wufeifei/cobra    //Py。源代码安全审计,支持PHP、Java等开发语言，并支持数十种类型文件。
- https://github.com/securego/gosec    //go.Go语言源码安全分析工具
- https://github.com/GoSSIP-SJTU/TripleDoggy    //C。c/c++/object-c源代码检测框架，支持接口调用
- https://github.com/presidentbeef/brakeman    //Ruby on Rails应用静态代码分析
- https://www.kanxue.com/book-38-438.htm/    //第三课：Delphi代码审计--项目实战1
### JS代码审计应用安全
- https://github.com/RetireJS/grunt-retire    //js.js扩展库漏洞扫描
- https://github.com/Aurore54F/JaSt    //使用语法检测恶意/混淆的JS文件，https://www.blackhoodie.re/assets/archive/JaSt_blackhoodie.pdf
- https://github.com/ctxis/beemka    //针对Electron App的漏洞利用工具包
- https://github.com/doyensec/electronegativity    //Electron应用代码审计，App的错误配置和安全问题
- https://github.com/callforpapers-source/jshole/    //Js。js漏洞扫描。
### php代码审计应用安全
- https://github.com/euphrat1ca/SeaySourceCodeCheck    //C#。PHP代码审计,法师Seay源代码审计系统2.1版本.noupdate.
- https://github.com/OneSourceCat/phpvulhunter    //php.静态php代码审计.noupdate.
- https://github.com/ripsscanner/rips    //php.php代码审计工具.noupdate.
- https://github.com/chuan-yun/Molten    //C。PHP应用透明链路追踪工具。G:Qihoo360/phptrace;
- https://github.com/elcodigok/wphardening    //py.WordPress插件代码审计
### python代码审计应用安全
- https://github.com/ga0/pyprotect    //C++。给python代码加密，防止逆向。
- https://github.com/pyupio/safety    //Py。检查所有已安装 Python包，查找已知的安全漏洞
- https://github.com/facebook/pyre-check/    //Py3。facebook推出的Zoncolan基本版python代码静态审计工具。号称30分钟扫描一亿行代码库，bug漏洞都能找。
- https://github.com/shengqi158/pyvulhunter    //Py。基于pysonar2的Python应用审计。NOUPDATE。G:yinwang0/pysonar2;--
- https://github.com/PyCQA/bandit    //Py。python代码安全漏洞审计
- https://github.com/python-security/pyt    //Py。用于检测Python Web应用程序中的安全漏洞的静态分析工具
## 压力测试DDOS/CC/拒绝服务
- https://github.com/ywjt/Dshield    //Py。DDOS防护
- https://github.com/NewEraCracker/LOIC/    //C#。基于Praetox's LOIC project的压测工具，使用mono进行跨平台。
- https://github.com/IKende/Beetle.DT    //C#。分布式压力测试工具
- https://github.com/649/Memcrashed-DDoS-Exploit    //Py。利用shodan搜索Memcached服务器进行压力测试
- https://github.com/jseidl/GoldenEye    //Py。DOS测试
- https://github.com/mschwager/dhcpwn    //Py。DHCP/IP压力测试
- https://github.com/Microsoft/Ethr    //Go。跨平台，TCP， UDP， HTTP， HTTPS压力测试工具
- https://github.com/Markus-Go/bonesi    //C。模拟僵尸网络进行ICMP/UDP/TCP/HTTP压测
- https://github.com/ajmwagar/lor-axe    //RUST.多线程、低带宽消耗的HTTP DoS工具
- https://github.com/EZLippi/WebBench    //C。网站压力测试，最高并发3万
- https://github.com/jagracey/Regex-DoS    //RegEx拒绝服务扫描器
- https://github.com/algo7/bluekeep_CVE-2019-0708_poc_to_exploit    //Py。RDP服务远程命令执行/DOS攻击/蓝屏exp
- http://www.yykkll.com    //压测站评测。W:defconpro.net;W:vip-boot.xyz
- https://rocketstresser.com/login.php    //多协议，支持cdn测试
- https://klionsec.github.io/2017/11/15/hping3/    //HPing3网络工具组包
# wiki_FreeConnect
- https://github.com/euphrat1ca/security_w1k1/blob/master/wiki_FreeConnect.md/    //通讯工具技术相关.myWiki
# wiki_Selfsource
- https://github.com/euphrat1ca/security_w1k1/blob/master/wiki_Selfsource.md/    //自服务应用在线资源、文件\url\节点检测.myWiki
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
## 端口转发流量代理
- https://github.com/euphrat1ca/security_w1k1/blob/master/wiki_SocketProxy.md    //端口映射，代理穿透，流量代理转发
## 欺骗防御
- https://github.com/euphrat1ca/security_w1k1/blob/master/wiki_HoneyPot.md.md/    //欺骗防御、蜜罐、主动反制。myWiki
## 逆向安全分析
- https://github.com/euphrat1ca/security_w1k1/blob/master/wiki_SecReverse.md/    //逆向分析、反编译、破解。myWiki
## 漏洞收集
- https://github.com/euphrat1ca/security_w1k1/blob/master/wiki_VulExp.md/    //web漏洞、软件模板漏洞、数据库、中间件、CMS框架漏洞、MS&Linux等系统组件漏洞、IOT漏洞收集表单。myWiki
## web安全前端利用
- https://github.com/euphrat1ca/security_w1k1/blob/master/wiki_WebSecurity.md/    //web安全测试利用、前端安全、数据库sql注入、xss跨站、上传漏洞、命令注入执行、webshell、https证书加密、web应用扫描器框架。myWiki。
## 拓展插件相关工具
- https://github.com/euphrat1ca/security_w1k1/blob/master/wiki_ToolDevelop.md/    //kali/nmap/burpsuite/Nessus/awvs/sqlmap/metasploit/cobaltstrike/empire/菜刀/ 插件.mywiki
---
# 博客论坛信息流
- https://i.hacking8.com/    //安全信息流。
- http://wiki.ioin.in/    //sec-news 安全文摘信息流。W:xj.hk;W:buaq.net;W:xssav.com;W:sec.thief.one;W:osint-labs.org;--
- https://www.anquanke.com/vul    //安全客GitHub安全类目引擎，基于热度、时间，cve漏洞监控。goodjob。
- https://github.com/k4m4/movies-for-hackers    //安全相关电影
- https://github.com/Hack-with-Github/Awesome-Hacking    //GitHub万星推荐：黑客成长技术清单
- https://github.com/DropsOfZut/awesome-security-weixin-official-accounts    //网络安全类公众号推荐
- https://github.com/zhengjim/Chinese-Security-RSS/    //国内安全资讯的RSS地址
- https://github.com/topics/security    //GitHub安全类目。G:We5ter/Scanners-Box;--
- https://start.me    //数据聚合平台。P:p/X20Apn;P:p/GE7JQb/osint;P:p/rxRbpo/ti;
- https://www.malwareanalysis.cn/    //安全分析与研究 专注于全球恶意样本的分析与研究
- https://www.52pojie.cn/    //吾爱破解。W:bbs.125.la/ //精易求精;--
- https://www.lshack.cn    //工控安全入门
- http://scz.617.cn:8/network/    //青衣十三楼(飞花堂)，逆向。W:cnblogs.com/ssooking;--
- http://blog.leanote.com/snowming    //红队博客。W:lcx.cc //NuclearAtk核总;W:blog.orange.tw //橘子出品必属精品;--
<br>
TheEnd