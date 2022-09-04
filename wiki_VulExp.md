# 漏洞收集
- twitter搜索“#exploit”、“#0day”、“CVE RCE”    --EXP\POC来源
- https://sploitus.com/    --公开漏洞搜索引擎,goodjob。
- https://www.cvebase.com/poc    --漏洞poc统计站。
- https://github.com/offensive-security/exploitdb    --美国Offensive Security维护的'exploit-db.com'漏洞库，包含利用插件、漏洞场景、渗透测试系统 etc。G:/nomi-sec/PoC-in-GitHub;G:/offensive-security/exploitdb-bin-sploits --已编译漏洞执行文件;G:/HacTF/poc--exp;G:/DrunkenShells/Disclosures;G:/coffeehb/Some-PoC-oR-ExP;G:/hackerhouse-opensource/exploits;G:/Yang0615777/PocList;--
- https://packetstormsecurity.com/    --国外漏洞库
- https://github.com/vulnersCom/getsploit    --Py3。类似于searchsploit，通过各种数据库的官方接口进行payload的查找。
- http://wiki.peiqi.tech    --peiqi wiki-poc文库。G:/PeiQi0/PeiQi-WIKI-POC;--
- https://github.com/BaizeSec/bylibrary    --白阁文库漏洞库。W:wiki.bylibrary.cn;--
- https://wiki.0-sec.org/    --零组公开漏洞库。W:dream0x01.com/spear-framework;--
- https://wiki.wgpsec.org/    --狼组安全团队公开知识库，Web安全、CTF、红蓝对抗。
- https://github.com/Lcys/Python_PoC    --py3。poc、exp快速编写模板，有众多模范版本。
- https://github.com/qazbnm456/awesome-cve-poc    --2017-2018年漏洞详情。
- https://srcincite.io/exploits/    --Steven Seeley漏洞利用，Exchange、Microsoft。G:/sourceincite/sourceincite.github.io/tree/master/pocs;--
- https://github.com/scannells/exploits    --CVE-2020-27194 Linux提权；CVE-2019-8943 wordpress命令执行；CVE-2019-6977 PHP沙盒绕过。
## 漏洞市场/SRC/BugBounty
- https://www.zerodayinitiative.com/    --Firmware设备固件漏洞市场
- http://www.zerodium.com/    --灰色漏洞交易平台/0day市场
- https://0day.today    --零日漏洞市场
- https://code4rena.com/    --合约漏洞市场。W:HackenProof;W:Immunefi;W:Secureum;--
## 漏洞共享平台
- https://github.com/mai-lang-chai/Middleware-Vulnerability-detection    --CVE、CMS、中间件漏洞检测利用合集 Since 2019-9-15 until Now。goodjob。G:/zhzyker/exphub;--
- https://github.com/Mr-xn/Penetration_Testing_POC    --渗透测试相关POC、EXP、脚本、提权、工具。goodjob。
- https://github.com/Critical-Start/Team-Ares    --CVE-2018-10142;CVE-2018-6961;CVE-2019-7550;CVE-2020-3957;CVE-2020-5902;--
- https://shuimugan.com    --2016/06/24 13:25之前乌云Drops文章、漏洞公开详情。W:0day.life;W:bugreader.com    --国外厂商公开漏洞详情。
- https://blog.intigriti.com    --intigriti公司bug bounty文章和公开漏洞详情
- https://hackerone.com/hacktivity    --HACKER ONE公开漏洞详情
- https://dvpnet.io/lddt    --DVP去中心化区块链漏洞平台公开漏洞详情
- https://sec.ly.com/bugs    --同程安全公开漏洞详情
- https://zeroday.hitcon.org/vulnerability/    --台湾漏洞公开库。
- https://github.com/xiangpasama/JDSRC-Small-Classroom    --京东SRC小课堂系列文章，电商应用。
## 软硬固应用漏洞
- https://github.com/k8gege/PhpStudyDoor    --PhpStudy 2016 & 2018 BackDoor Exploit 官网被植入后门
- https://github.com/jas502n/CVE-2019-16759    -- (RCE) vBulletin 5.0.0 - 5.5.4 CVE-2019-16759
- https://github.com/LeadroyaL/ss-redirect-vuln-exp/    --Py。shadowsocks重定向漏洞、密文流破解。G:/edwardz246003/shadowsocks;--
- https://github.com/anbai-inc/CVE-2018-4878    --Adobe Flash Exploit生成payload
- https://github.com/numpy/numpy/issues/12759    --科学计算框架numpy命令执行RCE漏洞
- https://github.com/KishanBagaria/AirDoS    --Py3。基于opendrop的IOS AirDrop Dos,要求系统版本低于13.3。
- https://github.com/jiansiting/ripple20-poc    --通过ICMP包探测 CVE-2020-11896 Treck TCP/IP协议拒绝服务漏洞。
- https://github.com/th3gundy/CVE-2019-7192_QNAP_Exploit    --qnap Nas平台  Pre-Auth Root RCE
### 文本编辑器漏洞
- https://github.com/numirias/security/tree/master/data/2019-06-04_ace-vim-neovim    --Intro。文本编辑器Vim/Neovim任意代码执行漏洞。修改vimrc在50行这里添加一个“set modeline” 然后esc保存退出，然后执行```source ~/.vimrc```让它生效。
- http://blog.nsfocus.net/pdf-vul/    --利用pdf编辑器执行文件中的Javascript脚本。
### 浏览器漏洞
- https://github.com/ray-cp/browser_pwn    --浏览器二进制溢出漏洞利用。
- https://github.com/SkyLined/LocalNetworkScanner    --JS。浏览器漏洞扫描网站浏览者内网信息。
- https://github.com/0vercl0k/CVE-2019-9810    --命令执行Firefox on Windows 64 bits.
- https://github.com/exodusintel/CVE-2019-0808    --JS,C++。CVE-2019-5786 and CVE-2019-0808 Chrome 72.0.3626.119 stable Windows 7 x86 exploit chain.
- https://quitten.github.io/Firefox/    --利用浏览器(file:///home/user/) Bug使用钓鱼html读取客户端文件
- https://github.com/r4j0x00/exploits    --chrome漏洞，--no-sandbox下JS命令执行
- https://github.com/Puliczek/CVE-2022-0337-PoC-Google-Chrome-Microsoft-Edge-Opera    --敏感信息泄漏
### 远程管理工具漏洞
- https://github.com/blacknbunny/libSSH-Authentication-Bypass    --CVE-2018-10933 libssh服务端身份验证绕过。G:/leapsecurity/libssh-scanner;--
- https://www.jianshu.com/p/726a3791b5b9    --OpenSSH用户枚举漏洞（CVE-2018-15473）
- https://github.com/yogeshshe1ke/CVE/blob/master/2019-7690/mobaxterm_exploit.py    --Py。MobaTek MobaXterm Personal Edition v11.1 Build 3860窃取ssh密钥。CVE-2019-7690。
- https://github.com/cpandya2909/CVE-2020-15778    --Linux SCP复制命令加载恶意文件引起命令执行
- https://devel0pment.de/?p=1881/    --AnyDesk RCE UDP远程执行代码（CVE-2020-13160）。W:AnyDesk和TeamViewer在渗透测试中的应用;--
### 安全设备漏洞
- https://github.com/milo2012/CVE-2018-13379    --Py。FortiOS飞塔防火墙/VPN Pre-auth任意文件读取
- https://nosec.org/home/detail/2862.html    --Intro。如何攻击飞塔Fortigate SSL VPN
- https://github.com/projectzeroindia/CVE-2019-19781    --Citrix产品云服务智能网关vpn命令执行RCE
- https://github.com/jas502n/CVE-2020-8193    --Citrix云服务平台任意文件读取漏洞。
- https://blog.unauthorizedaccess.nl/2020/07/07/adventures-in-citrix-security-research.html    --CitrixSystems CVE-2020-8191;CVE-2020-8193;CVE-2020-8194;CVE-2020-8195;CVE-2020-8196;--
- https://github.com/projectzeroindia/CVE-2019-11510    --Pulse Secure SSL VPN上的任意文件读取（CVE-2019-11510）。GoodJob。
- https://github.com/mu0gua/VulnPOC    --OpenSSL心脏滴血heartbleed漏洞批量利用;cve-2019-2618 Weblogic;cve-2019-3395 Confluence;--

### 安全工具漏洞
- https://github.com/WyAtu/CVE-2018-20250    --Py。WinRAR压缩包代码执行复现与利用
- https://www.bamsoftware.com/hacks/zipbomb/    --ZIPBOMB压缩包炸弹
- https://www.exploit-db.com/exploits/39755    --Acunetix WVS 10 - Remote Command Execution远程命令执行
- https://www.secpulse.com/archives/18940.html    --Intro。Web Vulnerability Scanner 8 远程命令执行漏洞。本地使用wscript.shell组件执行命令。
- https://bbs.pediy.com/thread-195431.htm    --Intro。Pwn the n00bs - Acunetix 0day。awvs溢出攻击
- https://www.anquanke.com/post/id/176379    --Intro。蚁剑菜刀RCE。蚁剑客户端RCE挖掘过程及源码分析。Electron APP漏洞。
- https://nosec.org/home/detail/4526.html    --通过Web iframe标签利用TeamViewer，CVE-2020-13699。
- https://www.t00ls.net/articles-56337.html    --intro。冰蝎马 那可有可无的密码。冰蝎软件配置漏洞，免密码连接，增添agent头校验。
### 通讯设备漏洞
- https://github.com/r0eXpeR/supplier    --主流供应商的一些攻击性漏洞汇总
- https://github.com/dunderhay/CVE-2020-5902    --F5 Big-IP负载均衡RCE/LFI，常用于政企。G:/aqhmal/CVE-2020-5902-Scanner;G:/jas502n/CVE-2020-5902;--
- https://github.com/ZephrFish/F5-CVE-2022-1388-Exploit    --F5 iControl REST接口 CVE-2021-22986
- https://github.com/yassineaboukir/CVE-2018-0296    --测试思科ASA路径穿越漏洞，可获取系统详细信息。
- https://github.com/seclab-ucr/tcp_exploit    --利用tcp漏洞使无线路由器产生隐私泄露
- https://www.heibai.org/post/1395.html    --奇安信技术研究院。D-Link路由器HNAP协议系列漏洞披露。DNS劫持/命令注入/配置泄露/越权访问
- https://github.com/imjdl/CVE-2020-8515-PoC    --DrayTek路由器VigorSwitch命令执行RCE。
- https://github.com/yumusb/EgGateWayGetShell_py    --锐捷网络-EWEB网管系统 getshell。
### 通讯协议漏洞
- https://github.com/marcinguy/android712-blueborne    --CVE-2017-0781 安卓蓝牙远程代码执行。
### 万物互联漏洞
- https://github.com/ezelf/CVE-2018-9995_dvr_credentials    --CVE-2018-9995摄像头路由，Get DVR Credentials
- https://github.com/JrDw0/CVE-2017-7921-EXP    --海康身份验证绕过，信息泄露漏洞
- https://github.com/RUB-SysSec/SiemensS7-Bootloader    --西门子CVE-2019-13945工业设备漏洞。诊断模式任意代码执行。
### 沙盒虚拟机容器漏洞
- https://github.com/mtalbi/vm_escape    --C。cve-2015-5165/cve-2015-7504 VMware虚拟机逃逸。P:2020 VMware vCenter未授权任意文件读取 --ESXI;--
- https://github.com/unamer/vmware_escape    --C/C++。VMware WorkStation 12.5.5虚拟机逃逸。CVE-2017-4901/CVE-2017-4905。
- https://github.com/MorteNoir1/virtualbox_e1000_0day    --VirtualBox E1000 Guest-to-Host Escape逃逸。教程
- https://bugs.chromium.org/p/project-zero/issues/detail?id=1682&desc=2    --Ghostscript：基于漏洞CVE-2018-17961的-dSAFER沙盒逃逸技术
- https://github.com/Frichetten/CVE-2019-5736-PoC    --Go。Docker容器逃逸通过利用容器内覆盖和执行主机系统runc二进制文件。docker与runc有版本要求。G:/twistlock/RunC-CVE-2019-5736;W:Docker逃逸初探;公众号:Docker逃逸小结第一版;--
- https://staaldraad.github.io/post/2019-07-16-cve-2019-13139-docker-build/    --Docker代码编译命令执行 （CVE-2019-13139）
- https://unit42.paloaltonetworks.com/docker-patched-the-most-severe-copy-vulnerability-to-date-with-cve-2019-14271/    --Docker cp命令漏洞 (CVE-2019-14271)
- https://github.com/shogunlab/awesome-hyper-v-exploitation    --Hyper-V漏洞汇总
- https://github.com/hhc0null/GhostRule/blob/master/ghostrule4.ps/    --CVE-2019-10216: ghostscript沙箱绕过命令执行漏洞
- https://github.com/hacksysteam/WpadEscape    --利用wpad进行浏览器 sandbox沙箱逃逸
### 云平台漏洞
1. https://github.com/wyzxxz/aksk_tool    --AK资源管理工具，阿里云/腾讯云 AccessKey AccessKeySecret，利用AK获取资源信息和操作资源，ECS/CVM操作/执行命令，OSS/COS管理，RDS管理，域名管理，添加RAM账号等
- https://www.cnblogs.com/xiaozi/p/11767841.html    --阿里云利用 由OSS AccessKey泄露引发的思考
- https://github.com/kkamagui/napper-for-tpm    --Py。针对TPM(可信平台防篡改设备模块)CVE-2018-6622漏洞利用工具。

## 应用组件漏洞
- https://github.com/uknowsec/BurpSuite-Extender-fastjson    --Burp插件。Java Bean序列化为JSON字符串，利用ceye对fastjson 1.2.24和1.2.47 RCE探测。W:/p1g3/Fastjson-Scanner;--
- https://github.com/CaijiOrz/fastjson-1.2.47-RCE    --Fastjson <= 1.2.47 远程命令执行漏洞利用工具及方法。G:/MagicZer0/fastjson-rce-exploit --利用jndi绕过autotype;G:/iSafeBlue/fastjson-autotype-bypass-demo;G:/wyzxxz/fastjson_rce_tool;G:/jas502n/fastjson-RCE;--
- https://www.cnblogs.com/tr1ple/p/11243640.html    --Imagetragick 命令执行漏洞（CVE-2016–3714）图片编辑器
### 办公软件漏洞
1. https://github.com/Nwqda/CVE-2022-26134    --Atlassian Confluence远程代码执行漏 CVE-2022-26134(Confluence OGNL表达式注入)
- https://www.corben.io/atlassian-crowd-rce/    --Java。atlassian crowd CVE-2019-11580。
- https://github.com/httpvoid/writeups/blob/main/Confluence-RCE.md    --CVE-2021-26084 Remote Code Execution

## Web应用漏洞
- https://github.com/r0eXpeR/redteam_vul    --红队中易被攻击的一些重点系统漏洞整理
- https://github.com/SecWiki/CMS-Hunter    --CMS工具漏洞测试用例集合。G:/Moham3dRiahi/XAttacker;G:/Mr5m1th/0day;G:/w1109790800/penetration;G/anx1ang/Poc_Pentest;--
- https://github.com/CHYbeta/cmsPoc    --CMS渗透测试框架。G:/chuhades/CMS-Exploit-Framework;--
- https://github.com/Tuhinshubhra/CMSeeK    --Py。WordPress,Joomla,Drupal等170余种CMS扫描识别检测。welljob。G:/Dionach/CMSmap;--
- https://github.com/blackye/Jenkins    --Jenkins系统监控框架漏洞探测、用户抓取爆破。
- https://github.com/orangetw/awesome-jenkins-rce-2019    --jenkins漏洞库，CVE-2018-1000861 CVE-2019-1003005 CVE-2019-1003029。
- https://github.com/petercunha/Jenkins-PreAuth-RCE-PoC    --jenkins远程命令执行。
- https://github.com/lijiejie/IIS_shortname_Scanner    --Py3。IIS短文件名漏洞扫描。G:/irsdl/IIS-ShortName-Scanner;--
- https://github.com/ajinabraham/NodeJsScan    --Py。NodeJS应用Web安全测试，查询可利用接口。WebUI。
- https://github.com/jas502n/CVE-2019-7238    --Nexus Repository Manager 3 Remote Code Execution without authentication < 3.15.0
- https://github.com/jas502n/CVE-2019-15642/    --CVE-2019-15642 Webmin远程命令执行，需要登录权限。
- https://slides.com/securitymb/prototype-pollution-in-kibana#/    --kibana <6.6.0 未授权远程代码命令执行。Kibana CVE-2019-7609 RCE Exploit。

- https://github.com/c0d3p1ut0s/CVE-2019-12086-jackson-databind-file-read    --CVE-2019-12086。利用jackson进行MySQL服务器任意文件读取漏洞
- https://github.com/RhinoSecurityLabs/CVEs    --CVE-2019-0227 Apache Axis RCE命令执行，AIX,EPSON,UNITRENDS,Memu,AudioCodes,Nvidia,CompleteFTP。
### Thinkphp漏洞
- https://github.com/theLSA/tp5-getshell    --Py2。thinkphp5 rce漏洞检测工具。
- https://github.com/SkyBlueEternal/thinkphp-RCE-POC-Collection    --thinkphp v5.x 远程代码执行漏洞-POC集合。
- https://github.com/Lucifer1993/TPscan    /Py3。thinkphp漏洞检测，已支持2019。
### Joomla漏洞
- https://github.com/momika233/Joomla-3.4.6-RCE    --Py。joomla 3 命令执行rce
- https://github.com/rezasp/joomscan    --Perl。基于OWASP的Joomla检测利用
### Wordpress漏洞
- https://github.com/wpscanteam/wpscan    --Ruby。wordpress漏洞扫描工具。G:/shadowlabscc/ProjectOpal;G:/swisskyrepo/Wordpresscan;G:/m4ll0k/WPSeku;--
- https://github.com/rastating/wordpress-exploit-framework    --wordpress漏洞框架。W:/Jamalc0m/wphunter;G:/UltimateLabs/Zoom;--
### Drupal漏洞
- https://github.com/a2u/CVE-2018-7600    --CVE-2018-7600 SA-CORE-2018-002 Drupal 7 命令执行
- https://github.com/jas502n/CVE-2019-6340    --Drupal8's REST RCE SA-CORE-2019-003 CVE-2019-6340
- https://github.com/immunIT/drupwn    --Drupal 信息收集与漏洞利用工具
### Discuz漏洞
- https://paper.seebug.org/1144/    --Discuz X3以后漏洞总结
- https://github.com/code-scan/dzscan    --首款集成化的Discuz扫描工具
### C#/.Net服务漏洞
- https://github.com/pwntester/ysoserial.net    --C#。配合PowerShell生成有效负载利用.Net反序列化漏洞
### Python服务漏洞
- https://github.com/ryu22e/django_cve_2019_19844_poc/    --py。Django任意密码重置
### Java框架漏洞
- https://github.com/threedr3am/learnjavabug    --java。Java安全相关的漏洞和技术demo
- https://github.com/x41sec/slides/blob/master/2019-bsides-stuttgart/YourStackTracesAreLeakingCVEs.pdf    --Java服务异常信息查询敏感信息和漏洞信息列表
- https://github.com/qtc-de/remote-method-guesser    --Java。枚举测试Java RMI（远程调用服务）安全。G:/NickstaDB/BaRMIe;--
- https://github.com/quentinhardy/jndiat    --Java。Java类名/目录接口/数据库审计检测
- https://github.com/frohoff/ysoserial    --java。用于生成反序列验证利用载荷。W:jackson-t.ca/runtime-exec-payloads.html/ 转化java加密指令;--
- https://github.com/Coalfire-Research/java-deserialization-exploits    --java反序列化漏洞收集，ciscoprime/jboss/jenkins/opennms/weblogic/websphere/ysoserial。
- https://github.com/GoSecure/break-fast-serial    --借助DNS解析来检测Java反序列化漏洞工具
- https://github.com/gquere/CVE-2020-7931    --py。Maven框架插件Artifactory模板ssti利用执行漏洞。
- https://blog.csdn.net/wo541075754/article/details/121899105    --CVE-2021-44228 JNDI log4j RCE
#### WildFly/Jboss中间件漏洞
- https://github.com/joaomatosf/jexboss    --Py。扫描和检测Jboss EXP安全漏洞。jexboss exp 工具集。
- https://www.freebuf.com/column/240174.html/    --Jboss漏洞利用。主要是未授权访问带来的文件上传（CVE-2007-1036、CVE-2010-0738、CVE-2006-5750、JBoss jmx-consoleHtmlAdaptor addURL() File Upload Vulnerability），与反序列化造成的命令执行（CVE-2015-7501、CVE-2017-7504、CVE-2017-12149、CVE-2013-4810）。
- https://github.com/joaomatosf/JavaDeserH2HC/    --Java。JBOSSMQ JMS 集群反序列化漏洞（CVE-2017-7504）
- https://github.com/hlldz/wildPwn/    --Py,Lua。jboss8更名为WildFly，默认管理控制台弱口令爆破。
#### Weblogic中间件漏洞
- https://github.com/jas502n/CVE-2020-14882    --CVE-2020–14882 Weblogic Unauthorized bypass RCE。G:/s1kr10s/CVE-2020-14882;--
- https://github.com/hktalent/CVE-2020-2551    --py。Weblogic IIOP反序列化命令执行漏洞（CVE-2020-2551）漏洞
- https://github.com/Maskhe/cve-2020-2555    --基于t3协议的Oracle Coherence&WebLogic反序列化远程代码执行。
- https://github.com/potats0/cve_2020_14644    --Java。CVE-2020-14644 Weblogic下Oracle反序列化回显利用
- https://github.com/jas502n/CVE-2018-2628/    --Weblogic 反序列化漏洞，通过T3协议命令执行。G:/5up3rc/weblogic_cmd;--
- https://github.com/21superman/weblogic_exploit    --Java。CVE_2015-CVE_2020，界面GUI。
- https://github.com/rabbitmask/WeblogicScan    --py3。Weblogic一键漏洞检测工具,包含CVE-2019前。
- https://github.com/dr0op/WeblogicScan    --Py3。weblogic系列漏洞扫描。最新支持CVE-2019-2618（DeploymentService接口任意文件上传）;CVE-2019-2729（XML反序列化rce命令执行）检测
- https://github.com/shack2/javaserializetools    --Java。Weblogic反序列化命令执行，```wls9_async_response```与```wls-wsat```组件无身份认证授权远程RCE漏洞。cve-2017-10271/CNVD-C-2019-48814/CNNVD-201904-961/CVE-2019-2725;
- https://github.com/pyn3rd/CVE-2018-3245    --weblogic cve-2018-2893与cve-2018-3245远程代码命令执行
- https://github.com/jas502n/CVE-2018-3191    --Weblogic CVE-2018-3191远程代码命令执行
#### Struts2框架漏洞
- https://github.com/shack2/Struts2VulsTools    --C#。Struts2漏洞检查工具。goodjob。G:/s1kr10s/Apache-Struts-v3;G:CVE-2020-17530-strust2-061;--
- https://github.com/PrinceFPF/CVE-2019-0230    --Apache Struts 2的远程代码执行漏洞EXP（CVE-2019-0230）st2-059
- https://github.com/Lucifer1993/struts-scan    --Py。Struts漏洞批量验证st2 005-057。
#### SpringBoot框架漏洞
- https://paper.seebug.org/1422/    --深信服千里目安全实验室 Spring 全家桶各类 RCE 漏洞浅析
- https://github.com/LandGrey/SpringBootVulExploit/    --SpringBoot漏洞学习资料，利用方法和技巧合集，黑盒安全评估 checklist。
- https://github.com/r00tuser111/ActuatorExploitTools/    --攻击spring boot actuator的集成环境，三种方式，仅支持攻击spring boot 1.x。
#### Tomcat框架漏洞
- https://github.com/euphrat1ca/CVE-2019-0232    --Apache Tomcat Remote Code Execution on Windows - 需要开启CGI-BIN。
- https://github.com/magicming200/tomcat-weak-password-scanner    --Py。tomcat后台弱口令扫描器，命令行版+图形界面版。
- https://github.com/00theway/Ghostcat-CNVD-2020-10487    --tomcat幽灵猫CVE-2020-1938高危文件读取、包含漏洞。
- https://tomcat.com/examples/jsp/snp/snoop.html    --tomcat信息泄露、实例文档、session样例操纵。
#### Shiro安全框架漏洞
- https://paper.seebug.org/shiro-rememberme-1-2-4/    --Intro。Apache Shiro Java安全框架 RememberMe 1.2.4 反序列化导致的命令执行漏洞。
- https://github.com/brianwrf/hackUtils    --Py。Apache Shiro RememberMe  1.2.4 Remote Code Execution；Jenkins CVE-2016-0792；S2-032；Joomla 1.5 - 3.4.5版本。G:/wyzxxz/shiro_rce;--
- https://github.com/feihong-cs/ShiroExploit/    --Java。Shiro550（硬编码秘钥）和Shiro721（Padding Oracle）检测，配合dnslog记录、shiro-urldns回显。G:/nsightglacier/Shiro_exploit;G:/potats0/shiroPoc;--
- https://github.com/j1anFen/shiro_attack    --Shiro反序列化漏洞综合利用。界面GUI。
- https://github.com/pmiaowu/BurpShiroPassiveScan    --Burp插件。被动检测shiro指纹。
#### Apache服务漏洞
- https://github.com/inbug-team/CVE-2021-41773_CVE-2021-42013    --Apache HTTP Server(2.4.49/2.4.50) RCE
- https://github.com/artsploit/solr-injection    --基于Lucene的全文搜索服务器Apache Solr Injection等漏洞集合研究。
- https://xz.aliyun.com/t/4452    --文件提取检测服务Apache tika命令执行CVE-2018-1335。
- https://github.com/mpgn/CVE-2019-0192    --Apache Solr远程命令执行漏洞。apache solr dataimporthandler RCE。jmx反序列化。
- https://github.com/jas502n/CVE-2019-12409    --CVE-2019-12409 Apache Solr RCE。Java ManagementExtensions（JMX）错误配置。
- https://www.freebuf.com/sectool/159970.html    --Apache Solr远程代码执行漏洞（CVE-2017-12629）从利用到入侵检测。XML外部实体扩展和命令执行。G:/wyzxxz/Apache_Solr_RCE_via_Velocity_template;--

## Web服务应用漏洞
- https://gist.github.com/Glassware123/1023720bf4787375a04f32a0c12e956a    --CVE-2020-12440_PoC nginx下http请求走私，干扰网站系统获取隐私数据。
### 网关接口CGI漏洞
- 通用网关接口（Common Gateway Interface/CGI）是一种重要的互联网技术，可以让一个客户端，从网页浏览器向执行在网络服务器上的程序请求数据。    --CGI描述了服务器和请求处理程序之间传输数据的一种标准。
- https://github.com/wofeiwo/webcgi-exploits    --Web CGI Exploits。php fastcgi；python uwsgi；PHP+nginx RCE（CVE-2019-11043） fastcgi。
- http://www.moonsec.com/post-389.html    --GNU BASH漏洞远程检测工具。cgi-bin/Bash Shellshock破壳漏洞CVE-2014-6271。

## 数据库应用漏洞
- https://github.com/euphrat1ca/CVE-2020-0618    --SQL Server Reporting Services利用```ysoserial.net```远程代码执行。
- https://github.com/oliver006/redis_exporter    --Go。redis未授权访问，主从复制写shell。
- https://github.com/r35tart/RedisWriteFile    --Py。通过 Redis 主从写出无损文件，可以写系统执行文件，也可以用无杂质覆写 Linux 中的 /etc/shadow。
- https://github.com/Dliv3/redis-rogue-server    --Redis 4.x/Redis 5.x RCE利用脚本，附带可利用so文件。G:/Ridter/redis-rce;G:/RicterZ/RedisModules-ExecuteCommand;--
- https://github.com/t0kx/exploit-CVE-2015-1427    --Bash。Elasticsearch 1.4.0 < 1.4.2 Remote Code Execution exploit and vulnerable container远程命令执行。P:/CVE-2014-3120 --v1.1.1支持传入动态脚本（MVEL）命令执行;--
- https://www.freebuf.com/vuls/212799.html/    --MongoDB未授权访问漏洞分析及整改建议
## Linux利用漏洞
- https://github.com/mudongliang/LinuxFlaw    --Linux软件漏洞列表
### Linux提权利用
- https://github.com/SecWiki/linux-kernel-exploits    --Linux kernel exploits。CVE-2004-2018年Linux平台提权漏洞集合。3k。G:/xairy/kernel-exploits --2017;G:/Kabot/Unix-Privilege-Escalation-Exploits-Pack --2014;G:/bcoles/kernel-exploits --2019;--
- https://github.com/cgwalters/cve-2020-14386    --Linux 5.9-rc4内核利用内存损坏来从非特权进程获取root特权。
- https://github.com/nmulasmajic/syscall_exploit_CVE-2018-8897    --Linux系统利用Syscall实现提权。G:/can1357/CVE-2018-8897;--
- https://github.com/jas502n/CVE-2018-14665    --linux下Xorg X服务器提权利用
- https://github.com/jas502n/CVE-2018-17182/    --Linux 内核VMA-UAF 提权漏洞
- https://github.com/0x00-0x00/CVE-2018-1000001    --冲区溢出 suid提权Ubuntu 16.04.3 LTS glibc <= 2.26。goodjob。
- https://github.com/RealBearcat/CVE-2017-16995    --内核注入代码提权Ubuntu 16.04.01 ~ 16.04.04 kernel 4.4 ~ 4.14。goodjob。
- https://github.com/euphrat1ca/CVE-2016-5195    --C++,Go。脏牛条件竞争写入只读(r)文件。Linux/Android 平台，release编译exp。goodjob。
- https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs    --C。脏牛提权漏洞exp集合wiki。Github:/FireFart/dirtycow --Linux Kernel 2.6.22 < 3.9（2007-2016年10月18日）;G:/gbonacini/CVE-2016-5195;--
- https://github.com/mschwager/0wned    --Py。利用Python包进行高权限用户创建。P:capabilities;--
- https://github.com/stanleyb0y/sushell    --利用su实现低权限用户窃取root用户口令。
## MS微软利用洞
1. https://github.com/nu11secur1ty/Windows10Exploits    --win10漏洞集合
- https://github.com/ZephrFish/CVE-2020-1350    --DNS Server远程代码执行漏洞（CVE-2020-1350），针对Windows Server等开启DNS服务的系统
- https://github.com/Sheisback/CVE-2019-0859-1day-Exploit/    --C++。CVE-2019-0859。可利用win32k.sys远程下载运行程序
- https://github.com/smgorelik/Windows-RCE-exploits    --windows命令执行RCE漏洞POC样本，分为web与文件两种形式
- https://github.com/3gstudent/CVE-2017-8464-EXP    --CVE-2017-8464，win快捷方式远程执行漏洞
- https://github.com/Lz1y/CVE-2018-8420    --Windows的msxml解析器漏洞可以通过ie或vbs执行后门
- https://github.com/Lz1y/CVE-2017-8759    --.NET Framework换行符漏洞，CVE-2017-8759完美复现（另附加hta+powershell弹框闪烁解决方案）。P:/freebuf.com/vuls/147793.html;--
- https://github.com/0x7556/txtdoor    --Windows漏洞，隐藏20年的txt后门。
- https://github.com/gentilkiwi/kekeo    --C。Kerberos漏洞利用工具箱，包括如MS14-068 (CVE-2014-6324) Kerberos 域控利用漏洞（“ systeminfo |find "KB3011780" 查看是否安装补丁”）。G:/mubix/pykek;G:/goldenPac.py;--
- https://github.com/padovah4ck/CVE-2020-0683    --C++。利用伪造MSI重写DACL访问控制列表、任意文件覆盖重写。
### Windows命令执行RCE
- https://github.com/jiansiting/cve-2020-16898    --CVE-2020-16898 (bad neighbor) ICMPv6 Windows TCP/IP远程代码执行。
- https://github.com/ZecOps/CVE-2020-0796-RCE-POC    --Python。Win10以下永恒之黑 - Windows SMBv3 LPE exploit #SMBGhost RCE&LPE。goodjob。G:/ollypwn/SMBGhost;G:/jiansiting/CVE-2020-0796;G:/chompie1337/SMBGhost_RCE_PoC;G:/danigargu/CVE-2020-0796;--。
- https://github.com/rapid7/metasploit-framework/pull/12283/    --CVE-2019-0708,四个文件进行BlueKeep漏洞利用，目前支持win7sp1/win2k8sr。msf插件。G:/coolboy4me/cve-2019-0708_bluekeep_rce --增加xp/03;G:/MS08-067;--
- https://github.com/3gstudent/Smbtouch-Scanner    --Py。MS17-010方程式永恒之蓝ETERNAL 445 SMB漏洞检测。
- https://github.com/hanshaze/MS17-010-EternalBlue-WinXP-Win10    --ms17010 winxp-win10全版本利用。
- https://github.com/countercept/doublepulsar-detection-script    --Py。方程式双倍脉冲RDP漏洞。
- https://github.com/afwu/PrintNightmare    -- (CVE-2021-1675)：域账户权限下Windows 后台处理程序服务中的远程代码执行
### Windows提权利用LPE
- https://github.com/SecWiki/windows-kernel-exploits    --Windows平台提权漏洞Exp集合。P:/kerberos域控ms14‐068/;G:/51x/WHP;G:/ianxtianxt/win-exp-/;G:/lyshark/Windows-exploits;--
- https://github.com/Ascotbe/Kernelhub    --Windows 提权漏洞合集，附带编译环境，演示GIF图，漏洞详细信息，可执行文件。goodjob。
- https://github.com/cube0x0/noPac    --普通域账号域内提权saMAccountName spoofing漏洞 CVE-2021-42287/CVE-2021-42278 Scanner & Exploiter.特权属性证书PAC
- https://github.com/antonioCoco/RemotePotato0    --利用DCOM激活服务，从一个普通用户提权至域管理员权限。
- https://github.com/lawrenceamer/0xsp-Mongoose    --PHP。提权枚举工具包，通过webApi上报信息。
- https://github.com/KaLendsi/CVE-2021-1732-Exploit    --C++。由函数win32kfull!xxxCreateWi ndowEx 对应用层回调返回数据校验不严导致，本地用户执行漏洞利用程序获取系统权限。
- https://github.com/dirkjanm/CVE-2020-1472    --NetLogon特权提升漏洞，一键域控提权。配合多个py文件set_empty_pw清空域控密码-secretsdump下载域控哈希secretsdump-restorepassword利用域管hash导出sam数据库原先哈希密码。G:/risksense/zerologon;G:/SecuraBV/CVE-2020-1472;--
- https://github.com/cbwang505/CVE-2020-0787-EXP-ALL-WINDOWS-VERSION/    --C++。Windows Background Intelligent Transfer Service (BITS)权限提升。
- https://github.com/RedCursorSecurityConsulting/CVE-2020-0668/    --C#。基于Service Tracing服务写入RASTAPI文件覆盖提权。
- https://github.com/cbwang505/CVE-2020-1066-EXP    --Windows CardSpace服务未正确处理符号链接对象导致的任意文件替换的本地权限提升漏洞，支持Windows 7和Windows Server 2008 R2操作系统。
- https://github.com/math1as/CVE-2020-1337-exploit    --Powershell。打印机重启调用系统功能，利用```mklink```绑定提权。G:/sailay1996/cve-2020-1337-poc;--
- https://windows-internals.com/printdemon-cve-2020-1048/    --利用打印机服务进行本地欺骗提权。G:/ionescu007/PrintDemon;--
- https://github.com/itm4n/PrintSpoofer    --C#。CVE-2020-1048，pipePotato基于LOCAL/NETWORK权限利用SeImpersonatePrivilege对win10/Server 2016/server 2019提权。G:/BeichenDream/BadPotato;--
- https://github.com/apt69/COMahawk    --C#。CVE-2019-1405 & CVE-2019-1322组合COM本地服务提权漏洞。win7-win10&win2k8-Windows Server 2019。
- https://gitee.com/cbwang505/CVE-2019-0803/    --Win7未正确处理GDI对象导致的UAF类型本地权限提升漏洞。
- https://github.com/alpha1ab/CVE-2018-8120    --```win32k.sys```组件的```NtUserSetImeInfoEx()```系统服务函数内部未验证内核对象中的空指针对象,普通应用程序可利用该空指针漏洞以内核权限执行任意代码。在win7与win2k8的基础上增加了winXP与win2k3。G:/unamer/CVE-2018-8120;--
- https://github.com/euphrat1ca/polarbearrepo    --C++。Win 10计划任务本地权限提升，win server 2016-2019提权，DACL权限覆写权限提升漏洞CVE-2019-0841。G:SandboxEscaper/polarbearrepo;G:3ndG4me/Win10-LPE;--
- https://github.com/uknowsec/SweetPotato    --C#。RottenPotatoNG变种烂土豆，利用com对象、用户token进行提权进行Windows 7 to Windows 10 / Server 2019提权，可用于webshell下执行命令。G:/CCob/SweetPotato;--
- https://github.com/breenmachine/RottenPotatoNG    --C++。CVE-2016-3225、烂土豆ms16-075，利用NBNS本地域名欺骗和WPAD代理欺骗提权。G:/decoder-it/lonelypotato;G:/foxglovesec/Potato;G:/ohpe/juicy-potato --testjob;G:/foxglovesec/RottenPotato;--
- https://github.com/WindowsExploits/Exploits    --微软CVE-2012-0217、CVE-2016-3309、CVE-2016-3371、CVE-2016-7255、CVE-2017-0213利用Windows COM提权。
- https://github.com/sam-b/CVE-2014-4113    --ms14-058利用'Win32k.sys'内核漏洞进行提取。
- https://github.com/taviso/ctftool/    --C。利用Windows文本服务框架（TSF）下CTF文本服务协议实现权限提升、沙箱逃逸、读写输入内容等。
- https://github.com/hausec/ADAPE-Script    --Active Directory权限提升脚本
- https://github.com/euphrat1ca/ms15-051    --C++。Windows 内核模式驱动程序中的漏洞可能允许特权提升 (3057191)，WS03-08。release。
- https://github.com/0xbadjuju/Tokenvator    --使用Windows令牌提升权限的工具，提供一个交互命令行界面
- https://github.com/klionsec/BypassAV-AllThings    --利用aspx一句话配合提权payload提权。
### Exchange漏洞利用
- https://github.com/ktecv2000/ProxyShell    --exchange无条件rce，CVE-2021-26857后续利用：写Dcsync ACL给指定域用户，导出域控哈希（secretdump.py），连接域控(psexec.py)。G:/dmaasland/proxyshell-poc;--
- https://github.com/Udyz/Proxylogon    --Exchange SSRF（CVE-2021-26855）
- https://github.com/Jumbo-WJB/CVE-2020-0688    --CVE-2020-0688_微软EXCHANGE服务的邮件远程代码执行漏洞。
- https://github.com/rapid7/metasploit-framework/pull/14126    --Microsoft Exchange Server DLP Policy RCE (CVE-2020-16875)
- https://www.anquanke.com/post/id/184342    --Exchange渗透测试总结。ruler拓展、ExchangeRelayX中继、mimikatz抓取、PasswordFilter注入劫持、mailsniper抓取、CVE-2018-8581提权、CVE-2019-1040绕过mic检测。W:blog.riskivy.com/exchange-server-in-pentest/;W:evi1cg.me/archives/Exchange_Hack.html;W:paper.seebug.org/833/;--
- https://github.com/WyAtu/CVE-2018-8581    --Py。利普通权限邮箱账号密码后，完成对其他用户(包括域管理员)邮箱收件箱的委托接管。利用```PrivExchange```与```ntlmrelayx```产生http->ldap中转实现的提权。
- https://www.freebuf.com/articles/network/238365.html/    --Exchange后渗透利用上篇。P:/articles/network/239026.html --Exchange后渗透分析下篇;--
#### Exchange接口利用
- https://github.com/sensepost/ruler    --Go。基于通过MAPI / HTTP或RPC / HTTP协议远程与Exchange服务器进行交互，只要拥有合法的用户凭证，就可以利用Ruler执行一系列的信息侦察、定向攻击、密码枚举。
- https://github.com/euphrat1ca/APT34-Jason    --C#。APT34针对exchange密码爆破。P:/对APT34泄露工具的分析——Jason;--
- https://github.com/johnnyDEP/OWA-Toolkit    --PS。利用Exchange爆破 ews接口（exchange web services）对Outlook Web App进行枚举爆破
- https://github.com/QuickBreach/ExchangeRelayX    --Py。基于flask\impacket，允许用户完成基于http的ntlm接口认证，并利用ews接口获取数据，IE浏览器可行。
- https://github.com/mullender/python-ntlm    --Py。利用Pass-the-Hash (PtH)直接到目标机器，exchange的ews接口支持ntlm认证，所以直接使用ntlm认证，使用ntlm hash去生成挑战值认证。
#### Exchange提权利用
- https://github.com/dirkjanm/PrivExchange    --Py。基于impacket，利用exchange提升system权限。CVE-2019-1040 Abusing Exchange: One API call away from Domain。
- https://dirkjanm.io/exploiting-CVE-2019-1040-relay-vulnerabilities-for-rce-and-domain-admin/    --INTRO。CVE-2019-1040利用PrivExchange漏洞产生smb->ldap中转，并且绕过MIC消息完整性检查。
- https://github.com/Yt1g3r/CVE-2020-0688_EXP    --Py。基于低权限账号进行ysoserial-远程代码执行。G:/Jumbo-WJB/CVE-2020-0688;G:/random-robbie/cve-2020-0688;--
### Office文档漏洞
1. https://github.com/bytecaps/CVE-2022-30190    --Microsoft Office Word Rce HTML 文件的外部 OLE 对象引用
   - CVE-2021-40444 MSHTML（又称Trident）是微软Windows操作系统Internet Explorer（IE）浏览器的排版组件。
- https://github.com/SecWiki/office-exploits    --office-exploits Office漏洞集合。
- https://github.com/Ridter/RTF_11882_0802    --Py。利用CVE-2017-11882与CVE-2018-0802组合漏洞生成hta二进制后门。
- https://github.com/Ridter/CVE-2017-11882    --利用word文档RTF获取shell，evi1cg.me/archives/CVE_2017_11882_exp.html。
- https://github.com/thom-s/docx-embeddedhtml-injection    --word2016，滥用Word联机视频特征执行恶意代码poc
- https://blog.cymulate.com/abusing-microsoft-office-online-video    --word2016，滥用Word联机视频特征执行恶意代码介绍
- http://www.freebuf.com/articles/terminal/150285.html    --无需开启宏即可在word文档中利用DDE（动态数据交换机制Dynamic Data Exchange）执行命令。G:/0xdeadbeefJERKY/Office-DDE-Payloads;--
- https://fuping.site/2017/04/18/CVE-2017-0199漏洞复现过程    --WORD RTF 文档，配合msf利用
- https://github.com/0x09AL/CVE-2018-8174-msf    --目前支持的版本是 32 位 IE 浏览器和 32 位 office。网页访问上线，浏览器关闭，shell 依然存活。W:freebuf.com/vuls/173727.html;--
- http://www.4hou.com/technology/9405.html    --在 Office 文档的属性中隐藏攻击载荷
- https://github.com/tezukanice/Office8570    --利用ppsx幻灯片远程命令执行。G:/rxwx/CVE-2017-8570;--
- https://evi1cg.me/archives/Create_PPSX.html    --构造PPSX钓鱼文件
- https://github.com/enigma0x3/Generate-Macro    --PowerShell。生成含有恶意宏的Microsoft Office文档
- https://github.com/mwrlabs/wePWNise    --生成独立于体系结构的VBA代码，用于Office文档或模板，并自动绕过应用程序控制
- https://github.com/curi0usJack/luckystrike    --PS。用于创建恶意的Office宏文档
- https://github.com/sevagas/macro_pack    --MS Office文档、VBS格式、快捷方式payload捆绑
- https://github.com/khr0x40sh/MacroShop    --一组通过Office宏传递有效载荷的脚本
- https://www.anquanke.com/post/id/163000    --利用Excel 4.0宏躲避杀软检测的攻击技术分析
- https://github.com/RhinoSecurityLabs/Security-Research/blob/master/tools/ms-office/subdoc-injector/subdoc_injector.py    --Py。配合responder利用word文档窃取ntlm哈希
- https://github.com/deepzec/Bad-Pdf    --Py。配合responder利用恶意pdf窃取ntlm哈希