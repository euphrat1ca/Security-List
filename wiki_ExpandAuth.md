# 后渗透
- https://github.com/rapid7/metasploit-framework    --Ruby。后渗透框架。greatjob。
## 绕过监控Bypass
- https://sec.thief.one/article_content?a_id=00883adf1ec3384c4040c37fa8ea01ec/    --公众号：绕过卡巴进程保护的一些总结。卡巴斯基绕过。
- https://blog.xpnsec.com/evading-sysmon-dns-monitoring/    --Intro。规避Sysmon DNS监控。
- https://github.com/ZanderChang/anti-sandbox    --Windows对抗沙箱和虚拟机的方法总结，沙箱绕过。
- https://github.com/tokyoneon/Chimera    --Powershll混淆绕过AMSI。welljob。
- https://github.com/leechristensen/UnmanagedPowerShell    --从非托管程序执行PowerShell，支持进程注入endpoint防护软件。
- https://github.com/CCob/SharpBlock/    --C#。使用DLL注入绕过EDR。
- https://x64sec.sh/understanding-and-bypassing-amsi/    --使用函数Hook和DLL注入绕过反恶意软件扫描接口(AMSI)组件。
- https://github.com/NYAN-x-CAT/Disable-Windows-Defender    --C#。Changing values to bypass windows defender。
- https://github.com/hfiref0x/UACME    --C。基于Failure-Free Method(FFM)绕过Windows用户帐户控制方法，支持多版本操作系统。
- https://github.com/sailay1996/UAC_Bypass_In_The_Wild    --利用Windows store bypass uac。
- https://github.com/St0rn/Windows-10-Exploit    --PY,msf插件。win10 UacByPass。
- https://github.com/swagkarna/Defeat-Defender    --Bat。利用“篡改保护”绕过Windows defender执行命令。

## 绕过防护Bypass
- https://github.com/AMOSSYS/Fragscapy    --Py。防火墙fuzz绕过bypass
- https://github.com/milo2012/ipv4bypass    --利用ipV6地址绕过waf
- https://github.com/3xp10it/bypass_waf    --防火墙绕过脚本
- https://github.com/sirpsycho/firecall    --直接向CiscoASA防火墙发送命令，无需登录防火墙后再做修改。
- https://github.com/pureqh/bypasswaf    --关于安全狗和云锁的自动化绕过脚本
- https://www.4hou.com/posts/oAAj    --WinRM与HTTP Server API的端口复用，利用IIS的端口共享功能绕过防火墙。基于http.sys实现权限维持。P:/"WinrmAttack.py";--
- https://github.com/Hackplayers/evil-winrm    --Ruby。利用WinRM shell进行soap协议传输绕过防火墙。
- https://github.com/ChrisAD/ads-payload    --利用环境变量与`destop.ini`绕过windows下的Palo Alto Traps派拓网络waf。
- https://www.4hou.com/posts/rMOp    --利用IIS的模块功能绕过防火墙。
- https://mp.weixin.qq.com/s/QJeW7K-KThYHggWtJ-Fh3w    --公众号：网络层绕过IDS/IPS的一些探索。分片传输，通过ipv6绕过ids/ips
- https://github.com/al0ne/Nmap_Bypass_IDS    --Nmap&Zmap特征识别，绕过IDS探测。
- https://github.com/kirillwow/ids_bypass    --IDS Bypass 脚本
- rasp绕过：JNI、DOS、开启线程（在新的线程里，没有当前请求的上下文）、黑名单、规则绕过

# 远程协助
1. https://github.com/BishopFox/sliver    --Golang。跨平台红队框架。G:/lwch/natpass;--
- https://www.thec2matrix.com/    --C2框架远控评测
- https://git.coding.net/ssooking/cobaltstrike-cracked    --OracleJava8。cobalt strike是一个APT协同工作平台，支持自定义域名host头绕过安全设备。greatjob。G:/Freakboy/CobaltStrike --源码;G:/rsmudge/armitage CobaltStrike社区版调用msf;G:/RASSec/Cobalt-Strike --3.14 Malleable-C2-Profiles;--
## C2通讯框架
- https://github.com/r00t-3xp10it/Meterpreter_Paranoid_Mode-SSL/    --Bash。Meterpreter Paranoid Mode - SSL/TLS connections https证书加密。
- https://www.freebuf.com/articles/network/142418.html/    --intro。绕过杀毒软件与主机入侵防御系统对流量的检测。
- https://green-m.me/2016/11/23/msf-paranoid-mode/    --intro。MSF偏执模式。
- https://labs.mwrinfosecurity.com/tools/c3/    --C++。红队C2通讯加密框架。
- https://github.com/Li4n0/revsuit    --Go。HTTP、DNS、RMI、MySQL 和 FTP 多协议反连平台。
### 多姿态远程协助
- https://blog.csdn.net/fly_hps/category_8913900.html    --FLy_鹏程万里【基础篇】-隐匿攻击之 ICMP/DNS/DropBox/Office 365/mail/app/webSocketSiteKeywordDomainApi/PS/WindowsDomWmi/webDav/https/images/JS/Proxy 等。
- https://github.com/0nise/shell-plus    --Java。基于 RMI 的一款服务器管工具，由服务端、注册中心、客户端进行组成。
- https://www.cnblogs.com/backlion/p/12272799.html    --MSSQL无落地文件执行Rootkit-WarSQLKit，获取具有"xp_cmdshell”，“ sp_OACreate”，“ sp_OAMethod”的sysadmin权限的帐户。G:/EPICROUTERSS/MSSQL-Fileless-Rootkit-WarSQLKit;--
- https://github.com/fox-it/LDAPFragger    --C#。利用ldap协议进行c2通讯。
- https://github.com/k8gege/WinrmCmd    --Go。Winrm远程命令/端口复用后门/WinrmCmd/密码爆破。WinRM是WindowsRemoteManagementd（win远程管理）的简称。基于Web服务管理(WS-Management)标准，使用80端口或者443端口。
- https://github.com/inquisb/icmpsh    --C。ICMP协议反弹shell。Github:/PiX-C2;--
- https://github.com/DamonMohammadbagher/NativePayload_ARP    --C#。利用arp协议传输后门。
- https://github.com/iagox86/dnscat2    --RUBY,C。利用DNS协议进行端对端通信。2k。goodjob。Github:/yarrick/iodine;Github:/lukebaggett/dnscat2-powershell;Github:/ahhh/Reverse_DNS_Shell;--
- https://github.com/sysdream/chashell    --Golang。利用dns反弹shell。
- https://github.com/sensepost/DNS-Shell    --Py。本地利用53端口nslookup传输加密的ps命令，回弹shell。
- https://github.com/Coalfire-Research/Slackor    --GO,Py3。基于slack框架命令控制，利用dns隐匿信道传输，集成spookflare/impacket/pypykatz。goodjob。
- https://github.com/peewpw/Invoke-PSImage    --PS。将PS脚本隐藏进PNG像素中后上传到web服务器，通过命令加载隐藏在图片里的载荷。1k。NoUpdate。Github:/et0x/C2;--
- https://github.com/h0mbre/Dali    --Py。利用图片像素进行C2服务器通讯，Image_Based_C2_PoC。
- https://github.com/deepzec/Grok-backdoor    --Py。利用ngrok的后门通信。
- https://github.com/trustedsec/trevorc2    --Py。通过搭建可浏览网站，隐藏命令执行的客户端/服务器通信。Github:/WebDAVC2;--
- https://github.com/byt3bl33d3r/gcat    --Py3。使用 gmail 作为 C&C 服务器。Github:/gdog;Github:/Powershell-RAT;--
- https://github.com/mvrozanti/RAT-via-Telegram    --Py3。Windows下利用telegram的远程控制工具。Github:/Parat;Github:/twittor;Github:/补bt2(Blaze Telegram Backdoor Toolkit);--
- https://github.com/0x09AL/Browser-C2    --Go。利用chrome以浏览器的形式连接C2服务器。
- https://github.com/Ramos-dev/OSSTunnel    --Java。利用云存储oss通信隧道的远程管理工具。
- https://github.com/reidmefirst/Modshaft    --Py2。利用modbus协议封装命令绕过防火墙。

## 跨平台远程协助
- https://github.com/geemion/khepri    --go。跨平台远程管理。welljob。G:/tiagorlampert/CHAOS;--
- https://github.com/n1nj4sec/pupy    --Py。Windows、Linux、OSX、Android跨平台多session。welljob。G:/nathanlopez/Stitch;G:/vesche/basicRAT;--
- https://github.com/its-a-feature/Mythic    --Py。Linux下跨平台远控。goodjob。
- https://github.com/cbrnrd/Kumo    --Java。基于jre环境的跨平台后门，一键编译，界面GUI。G:/ThatcherDev/BetterBackdoor;G:/BlackHacker511/BlackRAT;--
- https://github.com/zerosum0x0/koadic    --Py3。基于JScript/VBScript的大宝剑远控，多版本系统支持内存加载shell。GOODJOB。G:/shelld3v/JSshell/;--
- https://krober.biz/misc/reverse_shell.php?ip=127.0.0.1&port=8080/    --反弹shell命令生成器，利用pty、socat反弹交互式终端。G:/andrew-d/static-binaries/tree/master/socat;G:/sameera-madushan/Print-My-Shell;G:/WangYihang/Platypus;--
- https://github.com/0dayCTF/reverse-shell-generator/    js。反弹Shell命令一键生成
- https://github.com/BenChaliah/Arbitrium-RAT    --Py。Android、Windows、Linux三端远控。P:Arbitrium-WebApp;--
### Windows远程协助
- https://github.com/peterpt/fuzzbunch    --Py3。方程式NSA漏洞利用远控RAT，配有自动化安装脚本与界面GUI。永恒之蓝、永恒浪漫、永恒冠军、双星脉冲。
- https://github.com/yuanyuanxiang/SimpleRemoter    --C++,C。大灰狼gh0st的远程控制器。
- https://github.com/xdnice/PCShare    --C++。远程控制软件，可以监视目标机器屏幕、注册表、文件系统等。
- https://github.com/quasar/QuasarRAT/    C#。界面GUI。远程管理工具。G:/NYAN-x-CAT/AsyncRAT-C-Sharp;G:/TheSph1nx/RT-101;G:/DannyTheSloth/VanillaRat;G:/brunull/pace;--
- https://github.com/Mr-Un1k0d3r/ThunderShell    --Py3。Windows下远控，CLI与web端，内存加载，RC4加密HTTP传输。
- https://github.com/poweradminllc/PAExec    --C++。类Psexec远程$IPC控制。G:/nettitude/PoshC2;--
- https://github.com/lesnuages/hershell    --Go。反向TCP远程控制shell，https加密。G:/Ne0nd0g/merlin;G:/whitehatnote/BlueShell --已编译;G:/FlyfishSec/rsGen;G:/Tiked/Client;--
- https://github.com/bats3c/shad0w    --Py,C。支持Bypass AV、网站镜像、进程注入、https加密的C2框架。welljob。G:/r3nhat/GRAT2;G:/cobbr/Covenant;--
- https://github.com/ZHacker13/ReverseTCPShell    --PS。Windows下对tcp流量进行aes加密，增强版NC。G:/sweetsoftware/Ares;G:/5alt/ZeroRAT;--
- https://github.com/GuestGuri/Rootkit    --Py。反弹一个tcp连接，将进程id绑定到一个空文件夹。
- https://github.com/Ridter/MyJSRat    --Py3。利用js后门，配合chm、hta可实现很多后门方式。welljob。W:evi1cg.me/archives/chm_backdoor.html;G:/Hood3dRob1n/JSRat-Py --rundll 32加载;--
- https://github.com/lcatro/network_backdoor_scanner    --C++。反向连接内网穿透、通信加密、弱口令破解。
- https://github.com/3v4Si0N/HTTP-revshell    --Py。通讯加密、office组件payload模板生成。
### MacOS远程协助
- https://github.com/neoneggplant/EggShell    --Py。macos/osx远控，可生成HID代码，多session。testjob。noupdate。
- https://github.com/Marten4n6/EvilOSX    --Py。macos/osx远控，多session。testjob。noupdate。G:/creaktive/tsh --Tiny SHell;--
- https://github.com/tokyoneon/Armor    --Bash。macOS下利用加密Payload反弹Shell。
- https://github.com/its-a-feature/Apfell    --Py3。macOS与linux下的js后门利用。Web界面GUI。
- https://github.com/cedowens/MacC2    --mac osx远控
### 移动端远程协助
- https://spynote.us    --商业版。G:/hamzaharoon1314/SpyNote;--
- http://droidjack.net/    --商业版。
- https://github.com/AhMyth/AhMyth-Android-RAT    --Smali。Android平台一对多带界面。goodjob。
- https://github.com/The404Hacking/AndroRAT    --Java。Android平台一对多带界面。
- https://github.com/cleverbao/520apkhook    --对安卓APP注入MSF PAYLOAD，并且对手机管家进行BYPASS。
- https://github.com/home-assistant/home-assistant    --Py。物联网管理集群控制平台。
### 僵木蠕远程协助
- https://github.com/panda-re/lava    --批量恶意程序注入
- https://github.com/malwaredllc/byob    --僵尸网络生成框架
- https://github.com/deadPix3l/CryptSky/    --勒索病毒源码
- https://github.com/Ed1s0nZ/banana_blackmail/    --Go。勒索软件demo
- https://github.com/ReddyyZ/DeathRansom/       --Py3。基于PySide2界面的勒索软件，支持沙盒检测、反调试、反病毒
- https://github.com/jgamblin/Mirai-Source-Code    --C。MIRAI蠕虫病毒源码。
- https://blog.netlab.360.com/ttint-an-iot-rat-uses-two-0-days-to-spread/    --Ttint: 一款通过2个0-day漏洞传播的IoT远控木马。基于mirai。
- https://github.com/euphrat1ca/njRAT-v0.7d    --VB。常见蠕虫远控，多session带界面。G:/mwsrc/njRAT;G:/NYAN-x-CAT/Lime-RAT;--
- https://github.com/Egida/kek/blob/main/loader_multi.go    --BotenaGo僵尸网络。

## Shellcode利用
- https://github.com/ionescu007/r0ak    --内核层的瑞士军刀。在Windows10内核中读/写/执行代码。
- https://www.ascotbe.com/2020/04/18/ShellCode/    --TechTeach。恶意程序研究之定义ShellCode。
- https://paper.seebug.org/1413/    --techteach。如何实现一款 ShellCodeLoader。
### Shellcode注入加载
- https://www.shellterproject.com/    --动态Shellcode注入工具。商业版。
- https://github.com/Hzllaga/ShellcodeLoader/    --C#。Shellcode免杀、rsa加密、动态编译exe、反沙箱（检测父进程是否为Debugger）调试、远程文件注入，界面GUI。G:/ReddyyZ/GhostShell/;--
- https://github.com/knownsec/shellcodeloader    --C++。Windows平台的shellcode免杀加载器。G:/wetw0rk/Sickle;--
- https://github.com/3xpl01tc0d3r/ProcessInjection    --C#。指定进程注入shellcode，支持免杀。
- https://github.com/brimstone/go-shellcode    --Go。Windows内存加载shellcode执行。G:/sh4hin/GoPurple;G:clinicallyinane/shellcode_launcher/;--
- https://github.com/Zer0Mem0ry/RunPE    --C++。通过内存读取，网络传输内容，利用PE执行shellcode。
- https://github.com/monoxgas/sRDI    --Powershell。将DLL转换为shellcode反射加载，PE加载器引导，支持加密传输。testjob。
- https://github.com/anthemtotheego/C_Shot    --C。通过HTTP远程加载shellcode二进制文件（.bin），使用父进程欺骗将shellcode注入子进程执行。
### Shellcode免杀加载
- https://github.com/r00t-3xp10it/venom/    --Bash,PS。Linux下metasploit Shellcode generator/compiller，Unix/Win/Web/Apk/IOS/MSoffice多种类型利用程序生成。
- https://github.com/Rvn0xsy/Cooolis-ms    --Py。Cooolis-ms支持Metasploit Framework RPC的服务端，用于Shellcode和PE加载器工作，绕过反病毒软件的静态查杀，可让Cooolis-ms服务端与Metasploit服务器进行分离。
- https://github.com/TaroballzChen/Shecodject/    --Py3。将msf生成raw载荷封装注入，支持pem证书生成。
- https://github.com/3xpl01tc0d3r/Obfuscator    --C#。AES加密XOR混淆，支持base64、十六进制等格式shellcode。G:/EddieIvan01/gld;G:/DimopoulosElias/SimpleShellcodeInjector;G:/bats3c/DefensiveInjector;--
- https://github.com/byt3bl33d3r/OffensiveNim    --OffensiveNim之偏僻语言shellcode加载器。该语言可直接编译为C/C++/Objective-C和Javascript。goodjob。
- https://github.com/Mr-Un1k0d3r/DKMC/    --Py。Don't kill my cat，将shellcode混淆存储图像中。
- https://github.com/secretsquirrel/the-backdoor-factory    --PY,C。通过填充无用数据空间劫持DLL程序生成shellcode。NoUpdate。
- https://github.com/k-fire/shellcode-To-DLL    --C++。shellcode异或加密生成dll，类拿破轮胎DLL注入架构。界面GUI。welljob。G:/qH0sT/Ransomware-Builder-v3.0;G:/aaaddress1/RunPE-In-Memory;--
- https://research.nccgroup.com/2021/01/23/rift-analysing-a-lazarus-shellcode-execution-method    --Lazarus 利用uuid加载shellcode
- https://github.com/Inf0secRabbit/BadAssMacros    --C#。宏免杀，免杀宏代码。

## 文件免杀
- https://github.com/TideSec/BypassAntiVirus    --TechTeach。公众号：70.远控免杀专题(70)-终结篇。goodjob。
- https://www.freebuf.com/articles/system/249449.html    --TechTeach。Cobalt Strike Powershell过360+Defender上线
- https://github.com/trustedsec/unicorn    --Py。一键生成多种后门。G:/n00py/Hwacha;G:/ShutdownRepo/shellerator;G:/Kkevsterrr/backdoorme;--
- https://github.com/Screetsec/TheFatRat    --Java。msf免杀，支持searchsploit搜索。goodjob。G:/Screetsec/Vegile;G:/abedalqaderswedan1/aswcrypter;G:/MohamedNourTN/Terminator;G:/pasahitz/zirikatu;G:/govolution/avet;G:/GreatSCT/GreatSCT;G:/EgeBalci/HERCULES;--
- https://github.com/Veil-Framework/Veil    --Py。Msf免杀。goodjob。
### 文件打包捆绑
- wiki_TipSkill.md    --小众语言栈
- https://github.com/xZero707/Bamcompile    --C。将php文件打包为可执行文件绕过杀软，同理于其它服务文件类型。
- http://www.f2ko.de/downloads/Bat_To_Exe_Converter.zip    --将bat文件转换为exe二进制文件，可以隐藏窗口。G:/islamadel/bat2exe;G:/tywali/Bat2ExeConverter;G:/Juntalis/win32-bat2exe;--
- https://github.com/r00t-3xp10it/trojanizer    --将两个可执行文件打包为自解压文件，自解压文件在执行时会执行可执行文件
- https://github.com/r00t-3xp10it/backdoorppt    --将payload更换图标
- https://github.com/r00t-3xp10it/FakeImageExploiter    --将payload更换图标，需要wine与resourcehacker环境。
- https://github.com/DamonMohammadbagher/FakeFileMaker    --更换图标和名称
- https://github.com/deepzec/Bad-Pdf    --生成一个pdf文件，内含payload来窃取win上的Net-NTLM哈希
- https://github.com/3gstudent/Worse-PDF    --向PDF文件中插入恶意代码，来窃取win上的Net-NTLM哈希
- https://www.cnblogs.com/modou/p/3573772.html/    --NSIS - Windows安装程序制作工具，Nullsoft 脚本安装重制作安装包。
### 文件加密保护
- https://github.com/veracrypt/VeraCrypt    --C。类似于BitLocker架构全盘加密、磁盘隐藏分区、加密系统。W:veracrypt.fr;G:/FreeApophis/TrueCrypt;--
- https://vmpsoft.com/    --VMProtect ULTIMATE 3.4.0 Build 1155 文件套壳。
- https://github.com/upx/upx    --UPXShell（Ultimate Packer for eXecutables）文件压缩，通过动态配置文件增加到upx后续可以进行动态免杀。
- https://github.com/AlkenePan/KAP    --Go。实现 ELF 文件保护。goodjob。
- https://github.com/phra/PEzor    --CobaltStrike插件。基于Mingw-w64的PE文件加壳过杀软。
- https://bitwarden.com/    --跨平台密钥管理。G:/bitwarden/server;1Password、LastPass、Enpass;--
### 文件混淆免杀
- https://github.com/1y0n/AV_Evasion_Tool    --C#。掩日免杀执行器二进制、shellcode，配合`tdm64-gcc`生成。界面GUI。G:/TheWover/donut;--
- https://github.com/lengjibo/FourEye    --FourEye 重明免杀工具。
- https://github.com/9aylas/Shortcut-Payload-Generator    --快捷方式(.lnk)文件Payload生成器，AutoIt编写。
- https://github.com/pasahitz/regsvr32    --C#。使用C#+Empire实现最小体积免杀后门。
- https://github.com/Cn33liz/StarFighters    --基于DotNetToJScript，利用JavaScript和VBScript执行Empire Launcher。G:/mdsecactivebreach/CACTUSTORCH;--
- https://github.com/BinaryScary/NET-Obfuscate/    --C#。混淆.Net Framework程序。G:/0xd4d/dnlib;--
- https://github.com/unixpickle/gobfuscate/    --Go。加密二进制文件，混淆软件代码，清除Go编译时自带的信息。G:/burrowers/garble;G:/boy-hack/go-strip;--
- https://github.com/hlldz/SpookFlare    --Py。客户端与网络端策略绕过 msf/empire/koadic生成加载混淆免杀。
- https://github.com/hack2fun/BypassAV    --Cobaltstrike插件。基于`go build`生成免杀可执行文件。
- https://github.com/danielbohannon/Invoke-DOSfuscation/    --PS。cmd命令混淆。
- https://github.com/Mr-Un1k0d3r/MaliciousMacroGenerator    --VBA。宏混淆AV/Sandboxes绕过。
- https://github.com/danielbohannon/Invoke-DOSfuscation    --对powershell文件混淆，加密操作以及重新编码。G:/tokyoneon/chimera;G:/cwolff411/powerob;G:/OmerYa/Invisi-Shell;--
- https://github.com/the-xentropy/xencrypt    --ps。PowerShell 2.0以上 script anti-virus evasion tool，配合http协议格式绕过。
- https://github.com/Bashfuscator/Bashfuscator    --Py3。bash命令混淆。

## Linux渗透拓展
- https://github.com/TheSecondSun/Bashark    --Bash。Linux大鲨鱼后渗透框架。G:/DarkSpiritz/DarkSpiritz;G:/JusticeRage/FFM;--
- https://github.com/zMarch/Orc    --Bash。Linux下后渗透命令集合。G:/llamasoft/polyshell;--
## Windows渗透拓展
- https://github.com/EmpireProject/Empire    --PS。后渗透命令执行框架。GOODJOB。noupdate。G:/EmpireProject/Empire-GUI;G:/interference-security/empire-web;--
- https://github.com/samratashok/nishang    --PS。测试脚本集与开发框架。Check-VM检查虚拟机;Copy-VSS利用Volume Shadow Copy 服务来复制出SAM文件（密码）;Invoke-CredentialsPhish欺骗用户输入账号密码信息;FireBuster FireListener对内网进行扫描;Get-Information信息收集。testjob,3k。
- https://github.com/0xwindows/VulScritp    --内网渗透脚本，包括banner扫描、端口扫描;phpmyadmin、jenkins等通用漏洞利用等。G:/0xdea/tactical-exploitation;--
- https://github.com/xorrior/RemoteRecon    --基于DotNetToJScript进行截图、key记录、token窃取、dll与恶意代码注入。
- https://github.com/GhostPack    --C#。SpecterOps公司关于PowerShell 功能的各种 C# 实现的集合，包括Windows内网信息搜集\权限提升\密钥窃取等。
- https://github.com/4w4k3/Insanity-Framework    --Py2。Linux下的Windows沙箱绕过、杀软绕过、UAC绕过。NoUpdate。
- https://github.com/PowerShellMafia/PowerSploit    --PS。内网利用框架。反病毒特征码查询、DLL注入脚本、编码加密、记录窃取、权限维持、Windows提权、端口扫描。goodjob。Github:/PowerView;Github:/PowerUp;Github:/PowerTools;Github:/Shell-Suite;Github:/Misc-Powershell-Scripts;--
- https://github.com/rootm0s/WinPwnage    --UAC绕过、权限提升、权限维持。goodjob。
- https://github.com/quentinhardy/pytmipe    --Python功能库。令牌操作与权限提升。
- https://github.com/lengjibo/NetUser    --使用windows api添加用户，可用于net无法使用时，分为nim版、c++版本、RDI版、BOF版。
### Windows横向移动
- http://www.oxid.it/cain.html    --Cain & Abel。2017 4.9.56 NoUpdate。
- https://mp.weixin.qq.com/s/OGiDm3IHBP3_g0AOIHGCKA    --公众号：红蓝对抗之Windows内网渗透
- https://github.com/Cooolis/Cooolis.github.io    --Cooolis是一个操作系统命令技巧备忘录包含工具。qingxuan。W:cooolis.payloads.online;--
- https://github.com/nccgroup/redsnarf    --PS,Py。调用猕猴桃等程序窃取哈希，密码解密，rdp利用，远程启动shell，清除痕迹。
- https://github.com/byt3bl33d3r/CrackMapExec    --PY,PS。CME利用AD内置功能/协议规避大多数终端防护/IDS/IPS。包含impacket、PowerSploit等多种模块。testjob。G:SpiderLabs/scavenger;--
- https://github.com/S3cur3Th1sSh1t/PowerSharpPack/    --C#。将Seatbelt、Rubeus、SharpHound3、FakeLogonScreen、Safetykatz等工具，以base64编码的方式，集成到powershell脚本中调用。testjob。
- https://github.com/SecureAuthCorp/impacket    --Python功能库。Impacket用于处理网络协议、凭证移动利用。内网提权“wmiexec.py”，NMB、SMB1-3、MS-DCERPC等协议本身的低级别编程访问，凭证导出“secretsdump.py”。testjob。G:/maaaaz/impacket-examples-windows;--
- https://github.com/dirkjanm/krbrelayx    --Py。基于impacket和LDAP3的不受约束的授权滥用工具，配合exchange漏洞CVE-2019-1040。
- https://github.com/FortyNorthSecurity/WMImplant    --PS。利用WMI横向移动。Github:/FortyNorthSecurity/WMIOps;Github:/secabstraction/WmiSploit;--
- https://github.com/byt3bl33d3r/pth-toolkit    --Py。PTH(Pass The Hash)传递wmi移动。
- https://github.com/360-Linton-Lab/WMIHACKER    --VBScript。横向移动命令执行测试工具(只需135无需445端口，免杀)。
- https://github.com/QAX-A-Team/sharpwmi    --C#。基于rpc 135端口的横向移动工具，具有上传文件和执行命令功能。
- https://github.com/Mr-Un1k0d3r/SCShell    --跨平台基于ChangeServiceConfigA远程调用无文件横向移动工具。goodjob。
- https://github.com/GhostPack/Rubeus    --C#。Kerberos功能库，生成票据并注入。goodjob。G:/gentilkiwi/kekeo --PTK(Pass the ticket);--
- https://github.com/SkewwG/domainTools    --C,C++。内网域渗透资源约束委派。
### Windows凭证利用
- https://github.com/gentilkiwi/mimikatz    --C。Windows下获取权限、进入调试模式、注入lsass进程内容获取hash密码、获取凭证，进行横向移动PTH/PTK。GREATJOB。
- https://www.freebuf.com/articles/web/176796.html    --TechTeach。九种姿势运行Mimikatz
- https://www.freebuf.com/articles/system/250485.html    --TechTeach。手把手教你构建自定义的Mimikatz二进制文件。
- https://www.freebuf.com/articles/system/234365.html    --TechTeach。Mimikatz的18种免杀姿势及防御策略。G:/wanglaizi/ByPass_MIMIkatz;--
- https://github.com/skelsec/pypykatz    --Py3。Python实现的mimikatz
- https://github.com/klsecservices/bat-armor    --Py。生成mimikatz混淆版bat文件
- https://3gstudent.github.io/3gstudent.github.io/渗透技巧-Pass-the-Hash-with-Remote-Desktop-Protocol/    --使用hash登录RDP。借助mimikatz对mstsc，或使用xFreeRDP通过rdp服务、135端口服务进行hash传递（TCP/IP协议基础上的445、NBT协议基础上的137/8/9、RPC/wmi(只支持执行命令)
- https://github.com/eladshamir/Internal-Monologue    --C#。无需Mimikatz从LSASS进程内存中提取内容，直接从内存中提取明文密码、NTLM哈希、Kerberos ticket，以及执行pass-the-hash/pass-the-ticket攻击等。
- https://github.com/aas-n/spraykatz    --py3。Windows计算机和大型Active Directory环境中检索凭据的工具，对计算机进行`procdump（微软官方lsass内存dump工具）/sqldumper 官方mssql读取`，并远程解析转储。G:/outflanknl/Dumpert;--
- https://secpulseoss.oss-cn-shanghai.aliyuncs.com/wp-content/uploads/2015/04/ntdsdump/    --基于quarkspwdump加载`system.hiv`文件 获取密码。
- https://3gstudent.github.io/3gstudent.github.io/域渗透-获得域控服务器的NTDS.dit文件/    --导出`NTDS.DIT`文件，利用quarkspwdump、shadowcopy、NTDSDumpEx、ntdsxtract、Impacket-secretsdump进行读取system.hiv（hive）、`NTDS.dit`密码提取。
- https://wooyun.js.org/drops/导出当前域内所有用户hash的技术整理.html    --导出域内hash。
- https://github.com/Viralmaniar/HiveJack/    --C#。基于`c:\temp\`对Windows通过系统Hive来收集并导出SYSTEM、SECURITY和SAM注册表凭证导凭证信息，可清理痕迹自删除。testjob。
- https://github.com/lgandx/Responder    --Py。用于嗅探网络内所有的NTLM、NTLMv1/v2、Net-NTLMv1/v2包，对网络内主机进行欺骗获取用户hash。4k。
- https://github.com/Kevin-Robertson/Inveigh    --PS。LLMNR/mDNS/NBNS欺骗器。
- https://github.com/RhinoSecurityLabs/Security-Research/blob/master/tools/ms-office/subdoc-injector    --Py。构造恶意office文件，配合responder窃取凭证哈希。Security-Research作者的工具库。noupdate。
- https://blog.netspi.com/microsoft-word-unc-path-injection-image-linking/    --Intro。Microsoft Word – UNC Path Injection with Image Linking，word利用图片和responder窃取ntlm哈希
- 渗透技巧——Pass the Hash with Exchange Web Service/    --利用exchange web服务进行哈希传递。
- https://github.com/chroblert/domainWeakPasswdCheck    --ps。域账号弱口令审计。
- https://github.com/JoelGMSec/AutoRDPwn    --Ps4。远程桌面RDP协议利用。
- https://github.com/m8r0wn/ldap_search    --Py。通过ldap（轻量目录访问协议）认证，列举win域信息，爆破登录。
- https://github.com/NetSPI/ESC    --C#,PS。利用sqlserve数据库攻击系统。

## 文件搜集
- https://github.com/AlessandroZ/LaZagne    --py3。跨平台密码抓取工具。Win下V2.4相较于V2.3抓取到的内容会少一些。greatjob。
- https://github.com/moonD4rk/HackBrowserData    --Golang。跨平台浏览器密码、历史记录、书签、cookie抓取。goodjob。G:/QAX-A-Team/BrowserGhost;G:/hayasec/360SafeBrowsergetpass;--
- https://github.com/uknowsec/SharpDecryptPwd/    --对Navicat,TeamViewer,FileZilla(FTP),WinSCP,Xmangager系列（Xshell,Xftp)进行凭证抓取。GOODJOB。G:/z1Ro0/get_TeamViewer_ID_Password;--
- https://github.com/mrd0x/EvilSelenium    --chrome文件抓取、本地库读取。
- https://github.com/JDArmy/SharpXDecrypt    --Xshell全版本凭证一键恢复/密码解密
### Windows密钥收集
- https://github.com/AlessandroZ/LaZagneForensic    --LaZagne密码利用DPAPI破解升级版 需要Windows user密码。
- https://github.com/putterpanda/mimikittenz    --PS。类Lazagne架构密钥抓取，利用"ReadProcessMemory()"方法从目标进程中提取纯文本密码。G:/dafthack/DomainPasswordSpray;--
- https://github.com/tuthimi/quarkspwdump/    --C。quarkslab出品的密码抓取 hash dump，不用注入任何进程。已编译。G:/twelvesec/passcat;--
- https://github.com/G0ldenGunSec/SharpSecDump    --C#。远程SAM + LSA转储。
- https://github.com/nettitude/Invoke-PowerThIEf    --利用IE进行后渗透，抓取密码、重定向等。
- https://github.com/0x09AL/RdpThief    --C++。RDP密码抓取明文。G:/citronneur/rdpy;--
- https://github.com/Arvanaghi/SessionGopher    --PS。基于wmi进行WinSCP, PuTTY, SuperPuTTY, FileZilla, and Microsoft Remote Desktop密码抓取。
### Linux密钥搜集
- https://github.com/huntergregal/mimipenguin    --C。Linux密码抓取。
- https://www.cnblogs.com/KevinGeorge/p/12937328.html/    /intro。Linux内存凭据提取mimipenguin。
- https://github.com/mthbernardes/sshLooter    --ssh服务用户名密码窃取。'ssh knowhost免登录'

## 提权利用
- https://github.com/euphrat1ca/security_w1k1/blob/master/wiki_vul.md/    --相关提权漏洞。myWiki
- https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite    --hacktricks提权技巧总结。
- https://github.com/AlessandroZ/BeRoot    --Py。错误配置提权 Windows/Linux/Mac跨平台。
### Windows提权手段
- http://www.fuzzysecurity.com/tutorials/16.html    --windows平台教程级提权参考文章
- https://github.com/bitsadmin/wesng    --Py。WES-NG Windows Exploit Suggester Next Generation。基于Windows systeminfo给用户提供目标操作系统可能存在的漏洞列表，并针对这些漏洞给出漏洞利用实施建议，该工具的适用系统范围从Windows XP到Windows 10，还包括Windows Server等服务器/工作站版本。
- https://github.com/Pwnistry/Windows-Exploit-Suggester-python3    --将目标补丁程序级别与微软漏洞数据库进行比较，以检测目标上可能缺少的补丁程序，并查找可用的Metasploit模块
- https://github.com/rasta-mouse/Watson    --C#。查找Windows 10 & Server 2016 & 2019未打补丁。G:rasta-mouse/Sherlock;--
- 公众号：微软不认的“0day”之域内本地提权-烂番茄（Rotten Tomato）
- https://github.com/DanMcInerney/icebreaker    --处于内网环境但又在AD环境之外，icebreaker将会帮助你获取明文Active Directory凭据（活动目录存储在域控服务器可用于提权）
### Linux提权手段
- https://github.com/rebootuser/LinEnum    --Bash。对Linux系统可提权检测。goodjob,2k。Github:/linuxprivchecker;G:/jondonas/linux-exploit-suggester-2;Github:/belane/linux-soft-exploit-suggester;G:/nilotpalbiswas/Auto-Root-Exploit;G:/WazeHell/PE-Linux;--
- 内核漏洞、定时任务、Suid文件、Sudo 配置错误、NFS共享、第三方服务
- https://guif.re/linuxeop    --linux提权命令集合。P:/Ignitetechnologies/Privilege-Escalation --Linux下的提权方法总结;--
- https://github.com/berdav/CVE-2021-4034    --Linux polkit  pkexec提权

# 权限维持
- https://mp.weixin.qq.com/s/SavldFETaFea3l7kVX2RyA    --公众号：ATT&CK 之后门持久化
- https://www.secpulse.com/archives/100484.html    --Linux、Windows权限维持常用后门学习总结。P:/archives/103301.html/;--
- https://mp.weixin.qq.com/s/-cmM1k3--H6p1ditfQHPEw    --公众号：常见的Web容器后门笔记。iis后门/java框架后门/tomcat后门/apache后门/nginx后门/。G:/t57root/pwnginx;G:/0x09AL/IIS-Raid;G:/WBGlIl/IIS_backdoor;--
## Linux权限维持
- https://www.cnblogs.com/17bdw/p/10564902.html    --Linux后门权限维持手法，Linux后门总结-各类隐藏技能。G:/公众号:Linux常见的持久化后门汇总;--
- https://github.com/jivoi/openssh-backdoor-kit    --Bash。openssh后门编译生成。
- https://damit5.com/2020/02/22/cat的一个缺陷/    --利用`\r`回车符隐藏命令
### Linux文件隐匿
- https://github.com/f0rb1dd3n/Reptile    --C。LKM Linux rootkit隐藏植入。Testjob。
- https://github.com/mhaskar/Linux-Root-Kit    --Py。Linux隐匿rootkit。simple。
- https://github.com/gianlucaborello/libprocesshider    --C。利用'LD_PRELOAD'实现系统函数劫持，在linux下进程隐藏。goodjob。
- https://github.com/naworkcaj/bdvl/    --C。基于LDPRELOAD方式隐藏进程、命令、后门、反调试取证。testjob。G:/mempodippy/vlany/wiki --作者原知识库;--
- https://www.cnblogs.com/mysgk/p/9602977.html    --Intro。利用libprocesshider在 linux 下隐藏进程的一种方法。
- https://github.com/PinkP4nther/Sutekh    --C。rootkit隐匿普通用户权限获取root shell。

## Windows权限维持
- https://www.freebuf.com/vuls/195906.html/    --Windows常见后门持久化方式。P:/articles/system/229209.html;--
- https://github.com/jfmaes/Backdoorplz    --C++。Windows用户后门demo。
- https://pentestlab.blog/2020/01/13/persistence-image-file-execution-options-injection/    --att&ck Image File Execution Options Injection 通过注册表图像文件执行选项将调试器附加到应用程序并启用`GlobalFlag`进行应用程序调试。
### Windows签名伪造
- https://github.com/threatexpress/metatwin    --从一个文件中提取元数据，包括数字签名，并注入到另一个文件中
- https://github.com/Mr-Un1k0d3r/Windows-SignedBinary    --可以修改二进制文件的HASH，同时保留微软windows的签名
- https://github.com/secretsquirrel/SigThief    --Py。用于劫持合法的数字签名并绕过Windows的哈希验证机制的脚本工具
- https://github.com/secretsquirrel/SigThi    --Py3。伪造程序签名。
- https://github.com/netbiosX/Digital-Signature-Hijack    --通过劫持注册表，利用SIP DLL文件对执行文件进行数字签名。G:/mattifestation/PoCSubjectInterfacePackage --'MySIP.dll';--
### Windows白利用
- https://github.com/LOLBAS-Project/LOLBAS    --Windows系统白利用工具集。
- https://github.com/securemode/DefenderKeys    --枚举出被 Windows Defender 排除扫描的配置
- https://github.com/lucasg/Dependencies    --C#。基于"depends.exe"发现Windows exe dll文件依赖查询。goodjob。
- https://www.4hou.com/technology/16713.html    --通过模拟可信目录绕过UAC的利用分析\模拟可信目录的利用技巧扩展。
- https://github.com/g3rzi/Manifesto    --C#。寻找系统中存在可执行权限的组件。
- https://github.com/ufrisk/MemProcFS    --C。以访问文件系统的方式访问物理内存，可读写，有易于使用的接口. 当前支持Windows
- https://docs.microsoft.com/en-us/sysinternals/downloads/sigcheck    --通过查看```exe```的```manifest```查看程序执行权限，具有asInvoker highestAvailable requireAdministrator。
- https://bbs.pediy.com/thread-260539.htm    --TechTeach。杀软清除病毒对文件名过滤的不严格实现任意目录写任文件，符号链接攻击`mklink /d b <targetdir>`。
### Windows加载利用
- https://zhuanlan.zhihu.com/p/132644184    --Windows远程文件下载执行的15种姿势。PowerShell;Bitsadmin;certutil/InstallUtil;ipc$文件共享;mshta;rundll32;regsvr32/SCT文件;msiexec;`pubprn.vbs`;IEExec;`MSXSL.EXE`;FTP;TFTP;wget;WinScp;--
- https://www.freebuf.com/articles/system/155147.html    --Windows下载远程Payload并执行代码的各种技巧。WebDAV/Cmd;Cscript/Wscript;Regasm/Regsvc;Odbcconf;G:Arno0x/PowerShellScripts;--
- https://github.com/mdsecactivebreach/SharpShooter    --PY,VB,JS。基于DotNetToJScript生成检索和执行任意CSharp源码的payload，利用用XMLDOM去加载远程的`.xsl文件`。TESTJOB。
- https://github.com/p3nt4/PowerShdll    --使用rundll32运行PowerShell，绕过软件限制。
- https://github.com/tyranid/DotNetToJScript    --C#。能够利用JS/Vbs脚本加载'.Net'程序的工具。
- https://github.com/mdsecactivebreach/SharpPack    --C#。绕过系统应用白名单执行DotNet and PowerShell tools
- https://github.com/Ben0xA/nps    --C#。实现不调用'powershell.exe'执行powershell命令。G:/trustedsec/nps_payload;G:Mr-Un1k0d3r/PowerLessShell;--
### Windows DLL利用
- https://payloads.online/archivers/2018-12-22/1    --Intro。DLL Hijacking & COM Hijacking ByPass UAC - 议题解读。qingxuan。techteach。
- https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows    --Windows DLL劫持注入检查集。G:/wietze/windows-dll-hijacking;G:/jfmaes/TrustJack;--
- https://github.com/sensepost/rattler    --C++。自动化DLL文件注入，恶意DLL文件样例。TechTeach。G:/killvxk/infected_dll;--
- https://github.com/fatihsnsy/DLInjector-GUI    --C++。指定进程名注入DLL，支持等待进程启动注入。界面GUI。G:/rek7/dll-hijacking;P:/微软官方的dll注入工具Tracker;G:/tothi/dll-hijack-by-proxying;G:/Flangvik/SharpDllProxy;G/mrd0x/dll_inject_vs_binaries --微软签么注入--
- https://www.4hou.com/penetration/18447.html    --intro。域渗透——利用dnscmd在DNS服务器上实现远程加载dll文件。
- https://github.com/stephenfewer/ReflectiveDLLInjection    --C。不依赖于LoadLibraryA函数，将DLL库注入映射到目标进程内存。
- https://www.4hou.com/posts/wRPR    --深入分析 DLL 调用过程实现“自适应” DLL 劫持。techteach。
- https://github.com/uknowsec/ReflectiveDLLInjection-Notes    --反射DLL注入ReflectiveDLL。
- https://github.com/M00nRise/ProcessHider    --C++。Windows下dll注入隐藏进程id。
- https://github.com/itm4n/UsoDllLoader    --C++。Windows10 version 1903 USO服务每次创建Update Session时都会尝试加载不存在的DLL（windowscoredeviceinfo.dll）文件特权写入。
- https://xz.aliyun.com/t/2092    --Password Filter DLL在渗透测试中的应用。G:/3gstudent/PasswordFilter;--
- https://malicious.link/post/2013/2013-09-11-stealing-passwords-every-time-they-change/    --重启后加载Password Filter DLL。
### Windows进程注入
- https://github.com/lmacken/pyrasite    --Py3。对运行中dpython进程注入，支持≥py2.4。
- https://github.com/mdsecactivebreach/RDPInception/    --Bat,CS插件。基于tsclient服务进行rdp劫持，利用ps反弹shell。G:/bohops/SharpRDPHijack;--
- https://github.com/djhohnstein/CSharpSetThreadContext    --C#。可通过浏览器快捷方式中路径、当前路径进行恶意程序加载。goodjob。
- https://github.com/D4Vinci/PasteJacker    --剪贴板劫持利用工具。
### Windows文件隐匿
- https://github.com/islamTaha12/Python-Rootkit    --Py。Windows下rootkit远控，反弹meterpreter。
- https://github.com/eLoopWoo/zwhawk    --Windows下具备远程命令控制界面的内核rootkit。
- https://github.com/malcomvetter/UnstoppableService    --C#。将自身安装为Windows服务，且管理员无法停止/暂停svchost服务的程序。
- https://www.sans.org/blog/defense-spotlight-finding-hidden-windows-services/    --红队策略：隐藏Windows服务。
- https://github.com/jxy-s/herpaderping    --C++。通过修改镜像后映射的磁盘内容来掩盖进程执行。goodjob。

## 痕迹清理隐藏
- https://github.com/Rizer0/Log-killer    --Windows Linux 服务器日志清除
### Linux痕迹清除
- https://github.com/QAX-A-Team/ptrace/    --C。 Linux低权限模糊化执行的程序名和参数，避开基于execve系统调用监控的命令日志
- https://www.4hou.com/posts/Mo9R    --渗透基础——SSH日志的绕过，利用第三方语言原生库。
### Windows痕迹清除
- https://github.com/JusticeRage/freedomfighting    --日志清理、文件共享、反向shell。
- https://github.com/360-A-Team/EventCleaner    --日志擦除工具。
### MacOS系统清理
1. https://lemon.qq.com/    --腾讯柠檬清理。G:/rev1si0n/lamda;--