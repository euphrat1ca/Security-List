# 社会工程
- https://github.com/azizaltuntas/Camelishing    --Py3。社会工程学攻击辅助工具。WEBGUI。
- https://github.com/threatexpress/domainhunter    --通过bluecoat分类和`Archive.org`历史记录检查过期域名，选择钓鱼和C2域名。
- https://github.com/Mr-Un1k0d3r/CatMyPhish    --收集目标类似于的尚未注册的域名。
- https://github.com/Viralmaniar/I-See-You    --Bash。利用网站代理获取用户的真实地理信息。simple。
- https://www.jianshu.com/p/147cf5414851    --聊聊那些常见的探侦类APP。
### 输入监控
- https://github.com/Pickfordmatt/SharpLocker/    --c#。Windows锁屏密码记录。G:/bitsadmin/fakelogonscreen;PS:Invoke-LoginPrompt.ps1;PS:Invoke-CredentialsPhish.ps1;Koadic:password_box;Empire:collection/toasted;Empire:collection/prompt;MSF:phishwindowscredentials;--
- https://github.com/uknowsec/keylogger    --Go。OSS回传键盘记录。G:/mehulj94/Radium-Keylogger;--
- https://www.snapfiles.com/get/antikeyloggertester.html    --Windows客户端键盘记录工具AKLT。
- https://github.com/clymb3r/Misc-Windows-Hacking    --VS2019MFC编译工程。基于LSA调用PasswordFileter检查密码复杂性、调用PasswordChangeNotify同步密码，通过管理员权限DLL注入内存记录密码内容，通过修改`HookPasswordChange.cpp代码132行`修改输出路径。
- https://github.com/ggerganov/kbd-audio    --C++。Linux下利用麦克风捕获键盘输入，分析输入内容。goodjob。
- https://github.com/maxchehab/CSS-Keylogging    --Chrome扩展程序。Express服务器利用CSS进行键盘记录。
### 虚拟身份
- https://www.fakenamegenerator.com/    --多国身份信息模拟器
- https://github.com/gh0stkey/RGPerson    --Py。随机身份生成脚本
- https://xbeginagain.github.io/generator/    --编号生成器，身份证、营业执照、组织机构代码、统一社会信用代码、手机号、银行卡账号

## 钓鱼框架
- https://github.com/bhdresh/SocialEngineeringPayloads    --负责收集用于证书盗窃和鱼叉式网络钓鱼攻击的社交工程技巧和payloads
- https://github.com/trustedsec/social-engineer-toolkit    --Py。TrustedSec开发的专为社交工程设计的开源渗透测试框架，SET框架支持网站克隆、邮件伪造、反弹shell等。G:/Raikia/FiercePhish;/securestate/king-phisher;G:/tatanus/SPF;G:/fireeye/ReelPhish;G:/samyoyo/weeman;G:/MSG-maniac/mail_fishing;--
- https://github.com/fireeye/PwnAuth    --OAuth欺骗、凭证钓鱼、绵阳墙。G:/AlteredSecurity/365-Stealer;--
- https://github.com/ustayready/CredSniper    --使用Flask和Jinja2模板编写的网络钓鱼框架，支持捕获2FA令牌。G:/kgretzky/evilginx2/;G:/drk1wi/Modlishka;--
- https://github.com/thelinuxchoice/blackeye    --Py。拥有facebook、instagram等三十余个钓鱼模板的一键启用工具。
- https://github.com/M4cs/BlackEye-Python    --Py。基于blackeye增加子域名模拟伪造功能。
- https://github.com/gophish/gophish    --Go。拥有在线模板设计、发送诱骗广告等功能的钓鱼系统。G:/L4bF0x/PhishingPretexts;--
- https://github.com/euphrat1ca/SpoofWeb    --PHP。通过nginx反代一键部署office365、outlook、coremail、深信服等https钓鱼网站模板。G:/GemGeorge/SniperPhish;--
- https://github.com/thelinuxchoice/lockphish    --shell,PHP。基于ngrok利用钓鱼网站获取锁屏密码（手机、电脑）。
- https://github.com/xiecat/goblin    --Go。一键钓鱼演练工具，如flash弹窗更新伪造。G:/r00tSe7en/Flash-Pop;--
### 网站克隆
- http://www.httrack.com    --网站克隆镜像
- https://github.com/JonCooperWorks/judas    --Go。克隆网站钓鱼
- https://github.com/Rvn0xsy/Pricking    --网站反代钓鱼，敏捷启动，js功能插件。
### 邮件伪造
- https://github.com/SkewwG/henggeFish    --Go。自动化批量发送钓鱼邮件（横戈安全团队出品）
- https://mp.weixin.qq.com/s/RPz_1kKuq5--IANwT_Qvvg    --眼见不一定为实：对电子邮件伪造攻击的大规模分析。发件人策略框架（SPF）、域名密钥识别标准（DKIM）和基于域的消息验证、报告和一致性（DMARC）、UI保护机制 绕过。
- https://github.com/n0pe-sled/Postfix-Server-Setup    --自动化建立一个网络钓鱼服务器，Postfix/Sendmail邮件系统。
- https://emkei.cz    --在线邮件伪造，SPF&DKIM&DMARC协议多功能模拟。W:tool.chacuo.net/mailanonymous;--
W:ns4gov.000webhostapp.com;W:smtp2go.com/;--
- https://github.com/Macr0phag3/email_hack    --Py。钓鱼邮箱伪造。G:/lunarca/SimpleEmailSpoofer;G:/Dionach/PhEmail;--
- https://www.jetmore.org/john/code/swaks/    --Perl。基于smtp的邮箱域名伪造测试工具。
- https://www.ehpus.com/post/smtp-injection-in-gsuite/    --基于smtp注入的邮件欺骗。
### 服务密码爆破
- https://github.com/euphrat1ca/Fast-RDP-Brute-GUI-v2.0-by_Stas-M--Official/    --RDP密码爆破、扫描，Fast RDP Brute GUI by Stas M（解压密码Stas'M Corp）。W:stascorp.com;P:nlbrute 1.2;P:DUBrute;P:御剑RDP爆破工具v2.0;G:/7kbstorm/7kbscan-RDP-Sniper;P:Paessler SNMP Tester;--
- https://github.com/shack2/SNETCracker    --C#。超级弱口令检查工具，支持SSH、RDP、MySQL等常见协议。.G:/lijiejie/htpwdScan;--
- https://github.com/3gstudent/SharpRDPCheck    --C#。RDP爆破验证，支持ntlm登录验证。G:/najachai/RDPUploader;--
- https://github.com/ShawnDEvans/smbmap    --py。利用smb服务传递哈希、增删改查、命令执行、ip段共享枚举等。G:/m4ll0k/SMBrute;--
- https://github.com/InfosecMatter/Minimalistic-offensive-security-tools    --ps。smb、ad域密码爆破。
- https://github.com/nmap/ncrack    --C。Nmap协议弱口令爆破组件。G:/ztgrace/changeme;G:/netxfly/crack_ssh;G:/euphrat1ca/F-Scrack;G:/scu-igroup/ssh-scanner;--
- https://github.com/vanhauser-thc/thc-hydra    --C。支持多种协议方式的破解与爆破。;G:/maaaaz/thc-hydra-windows--
- https://github.com/jmk-foofus/medusa    --C。模块化端口爆破工具。G:/awake1t/PortBrute;--
- https://github.com/lanjelot/patator    --Py3。集成Hydra, Medusa, Ncrack, Metasploit modules and Nmap NSE验证爆破工具。
- https://github.com/galkan/crowbar    --Py。支持openvpn、rdp、ssh、vnc破解。G:/shengqi158/weak_password_detect;--
- https://github.com/TunisianEagles/SocialBox    --针对fb、gmail、ins、twitter的用户名密码爆破的脚本.
- https://github.com/Moham3dRiahi/XBruteForcer    --perl。WordPress、Joomla、DruPal、OpenCart、Magento等CMS爆破。
- https://github.com/ryanohoro/csbruter/    --3.10 cobaltstrike密码爆破。
- https://github.com/WBGlIl/CS_Decrypt    --cobaltstrike通讯流量解密脚本。
- https://github.com/theLSA/awBruter    --木马一句话爆破
- https://github.com/Ullaakut/cameradar    --Go。RTSP协议摄像头爆破字典。
- https://github.com/JrDw0/rtspBruter    --Py。rtsp密码爆破
### 测试字典集
- https://github.com/FlameOfIgnis/Pwdb-Public/    --多语言恶意软件常用密码分析。goodjob。
- https://github.com/klionsec/SuperWordlist/    --实战沉淀下的各种弱口令字典
- https://github.com/tarraschk/richelieu    --`.fr`邮箱密码表
- https://github.com/TheKingOfDuck/fuzzDicts/    --Web Pentesting Fuzz 字典。
- https://github.com/ihebski/DefaultCreds-cheat-sheet    --四千个中间件、网络设备默认密码字典。
- https://github.com/danielmiessler/SecLists    --用户名密码 URL敏感数据模式 模糊测试payload WebShell密码。G:/7dog7/bottleneckOsmosis;G:/Ridter/Pentest;G:/alpha1e0/pentestdb;--
- https://github.com/digininja/CeWL/    --Ruby。爬取目标网站关键词生成字典。
- https://github.com/brannondorsey/PassGAN    --Py。深度学习，密码字典样本生成
- https://github.com/Saferman/cupper    --Py。根据用户习惯密码生成弱口令探测。G:/Mebus/cupp;G:/LandGrey/pydictor;--
- https://github.com/HongLuDianXue/BaiLu-SED-Tool    --pascal。白鹿社工字典生成器
### 密码破解还原
- https://ophcrack.sourceforge.io/    --C。使用彩虹表Rainbow table来破解视窗操作系统（xp、vista）下的LAN Manager散列（LM hash）的计算机程序。
- https://securityxploded.com/download.php/    --各种密码解密方向工具。
- https://github.com/hashcat/hashcat    --C。哈希还原破解。greatjob。P:hashcat.net/cap2hccapx/ --cap转hccapx;--
- https://github.com/fireeye/gocrack    --Go。基于hashcat 3.6.0+的分布式密码破解工具。G:/f0cker/crackq;/s3inlc/hashtopolis;--
- https://github.com/chris408/known_hosts-hashcat    --Py。利用hashcat破解ssh密码hash。
- https://github.com/clr2of8/DPAT    --Py。利用hashcat等工具域密码进行破解测试。
- https://github.com/psypanda/hashID    --Py。超过220种hash识别。G:/AnimeshShaw/Hash-Algorithm-Identifier;--
- https://github.com/magnumripper/JohnTheRipper    --C。开膛手john利用已知密文破解明文密码。
- https://github.com/shinnok/johnny    --C++。John The Ripper Windows。界面GUI。
- https://www.52pojie.cn/thread-275945-1-1.html    --ARCHPR Pro4.54绿色中文破解版，利用已知明文破解加密压缩包。
- https://github.com/fox-it/adconnectdump    --Py。Azure AD凭证导出工具。
- https://github.com/DoubleLabyrinth/how-does-navicat-encrypt-password    --Navicate数据库密码解密。
- https://github.com/MrSqar-Ye/wpCrack    --wordpress hash破解
- https://github.com/TideSec/Decrypt_Weblogic_Password    --Java。WebLogic密码破解。G:/NetSPI/WebLogicPasswordDecryptor;--
- https://www.passfab.com/    --excel密码破解
- https://github.com/bdutro/ibm_pw_clear    --IBM x3550/x3560 M3 bios密码清除重置工具。
- https://github.com/thehappydinoa/iOSRestrictionBruteForce    --Py。实现的 ios 访问限制密码破解工具。
- https://github.com/e-ago/bitcracker    --C。首款开源的BitLocker密码破解工具
- https://www.ru.nl/publish/pages/909282/draft-paper.pdf    --Intro。破解SSD下使用BitLocker加密。
### 在线密码破解
- https://github.com/s0md3v/Hash-Buster    --调用多个API查询hash破解。
- https://github.com/testsecer/Md5Decrypt    --C#。基于web API的md5多接口查询搜索。
- https://www.cmd5.com/    --HASH密码在线破解。限制位数
- https://hashkiller.co.uk/Cracker    --密码破解。Google reCAPTCHA v3。
- http://hashtoolkit.com    --HASH密码在线破解。社区版
- http://md5.my-addr.com/md5_decrypt-md5_cracker_online/md5_decoder_tool.php    --md5密码破解。社区版。
- https://md5.gromweb.com/?md5=    --md5密码破解。社区版
- http://www.chamd5.org    --md5密码破解。需要登录。W:crack.sh;W:xmd5.org;W:pmd5.com;W:onlinehashcrack.com    --md5密码破解。需要验证码

## 信息隐匿保护
- https://github.com/ffffffff0x/Digital-Privacy/    --一个关于数字隐私搜集、保护、清理集一体的方案,外加开源信息收集(OSINT)对抗。类似于 wiki_OsintData；wiki_SelfServicerce；wiki_FreeConnect。goodjob。
- https://hackmd.io/@yBpKEsxORheI8AJoIiZj1Q/BkHtjA1k9    --Quick and Dirty Anon Building Guide 隐私框架快速搭建
- https://www.privacytools.io/    --常用隐私工具汇总
### 服务器隐匿
- https://github.com/leitbogioro/Fuck_Aliyun    --关闭阿里云监控服务
- https://www.anquanke.com/post/id/195011    --暗度陈仓：基于国内某云的 Domain Fronting 技术实践。CDN域前置。
- https://www.freebuf.com/sectool/232555.html    --利用Cloudflare Worker来隐藏C2基础设施。CDN域前置。G:/Berkeley-Reject/workers-proxy;--
- https://www.anquanke.com/post/id/220868    --TechTeach。利用heroku（容器云平台）服务器隐藏C2。
- https://mp.weixin.qq.com/s/Vrd8hWgPnK1bh1Ggj33NtQ    --基于NKN网络匿名远控。P:CobaltStrike 区块链网络上线方式及检测;G:/Maka8ka/NGLite;G:/nknorg/nkn-tunnel;--
### 隐匿流量洋葱路由
1. https://www.torproject.org/    --洋葱浏览器。P:/dnmugu4755642434.onion/ kilos搜索引擎;--
2. https://github.com/cretz/bine    --Golang。go语言的tor控制sdk
- https://github.com/globaleaks/Tor2web    --darkweb暗网代理服务器，将onion的服务变为普通的服务
- https://github.com/milesrichardson/docker-onion-nmap    --使用nmap扫描Tor网络上隐藏的"onion"服务
- https://github.com/GouveaHeitor/nipe    --一个使所有流量通过Tor网络发出的脚本
- https://github.com/Edu4rdSHL/tor-router    --Bash。使用tor代理全部流量。dnsleaktest.com dns检测。
- https://github.com/trimstray/multitor    --Bash。启用多个TorBrowser通道转发流量，并设置负载均衡
- https://github.com/NullArray/NetSet    --Bash。终端多路复用器，其会话通过Tor路由，并通过自动安装和配置DNSCrypt-proxy来保护DNS流量。

## 主动防御
- https://tom0li.github.io/反制攻击队和防守人员/    --防守反制
- Bot扫描肉鸡->捕获IP->捕获payload->防守反击
### 主动反制识别
- https://github.com/cnrstar/anti-honeypot    --Chrome插件。检测WEB蜜罐并阻断请求
- https://github.com/iiiusky/AntiHoneypot-Chrome-simple    --Chrome插件。蜜罐检测，Jsonp漏洞防御。
- https://www.freebuf.com/articles/ics-articles/230402.html    --一种工控蜜罐识别与反识别技术研究与应用实践。
### 攻击人物画像
- https://github.com/Valve/fingerprintjs2    --JS。被动式浏览器全指纹库获取。goodjob。Browser Fingerprinting via OS and Hardware Level Features。
- https://github.com/Song-Li/cross_browser    --JS。被动式跨浏览器指纹追踪识别，支持硬件特征（显卡、cpu核数等）识别。P:指纹追踪技术—跨浏览器指纹识别;P:/crossbrowsertracking_NDSS17.pdf;--
- https://www.yalala.com/    --浏览器指纹在线检测网站
- https://www.anquanke.com/post/id/216259    --设备指纹指南 上下。P:/post/id/216262;--
- https://github.com/WMJonssen/Centcount-Analytics    --PHP。数据库mysql/redis，网站分析软件，支持浏览器指纹、事件追踪、鼠标轨迹。
- https://github.com/jbtronics/CrookedStyleSheets    --php。使用CSS实现网页追踪 / 分析，用户鼠标轨迹捕捉。
- https://github.com/diafygi/webrtc-ips    --利用WebRtc服务获取内外网真实IP。W:whoer.net --web应用指纹获取集合;--
- https://www.anquanke.com/post/id/152339    --JSONP和CORS跨站跨域读取资源的漏洞利用（附带EXP）。JSON Hijacking实战利用多种利用方式。
- https://github.com/gh0stkey/ahrid    --py。利用jsonp等漏洞通过分析模块对黑客画像溯源。
- https://github.com/jonasstrehle/supercookie    --利用favicon进行F-Cache读取，构建唯一ID。
- 使用javascript确认对方是否开burpsuite    --img标签遍历burpsuite的favicon.ico文件，遍历“http:burp”
- https://github.com/NS-Sp4ce/MoAn_Honey_Pot_Urls    --社交蜜罐JSonp劫持所需API
### 攻击反制利用
- https://medium.com/tenable-techblog/reverse-shell-from-an-openvpn-configuration-file-73fd8b1d38da    --Intro。从OpenVPN配置文件中创建反弹Shell实现用户系统控制。W:freebuf.com/articles/terminal/175862.html;--
- https://www.exploit-db.com/exploits/38847    /如何优雅的反击扫描你网站的黑客。CVE-2015-4027,Acunetix WVS 10 - Local Privilege Escalation本地提权漏洞。
- https://blog.csdn.net/ls1120704214/article/details/88174003    --Go。反击mysql蜜罐。利用MySQL LOCAL INFILE读取客户端文件漏洞分析并使用Golang编写简易蜜罐;从MySQL出发的反击之路;Github:/MysqlT，支持大文件无损传输，支持用户验证，支持自定义的 Mysql 版本，随机的盐加密，加上用户验证，让攻击者毫无察觉;Github:/Rogue-MySql-Server;--
- https://github.com/qigpig/MysqlHoneypot    --Py。利用mysql读取文件。P:『红蓝对抗』利用蜜罐获取攻击者微信ID及手机号
 --1、从C:/Windows/PFRO.log中读取用户名；2、从C:/Users/用户名/Documents/WeChat Files/All Users/config/config.data中读取wx_id；3、从C:/Users/用户名/Documents/WeChat Files/wx_id/config/AccInfo.dat中读取微信绑定的手机号；4、根据 wx_id【'weixin://contacts/profile/'+wxid】可生成微信二维码用于可添加好友，根据实际测试，就算关掉了所有好友申请条件，仍可通过此二维码发起好友申请。
- https://www.freebuf.com/articles/system/232669.html    --内网Kerberos用户蜜罐。
- https://www.cnblogs.com/k8gege/p/12390265.html    --看我如何模拟Cobalt Strike上线欺骗入侵者。
- https://www.4hou.com/posts/Xnvk    --Win 10主题可以用来窃取密码，微软拒绝修复。
- https://mp.weixin.qq.com/s/7bbdHCCtS_7fsXFFW1LprQ    --XMind 2021 11.0 Beta 1 XSS漏洞导致命令执行
- https://github.com/Tylous/ZipExec    --通过密码保护的zip文件执行利用程序