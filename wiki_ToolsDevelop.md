# 相关工具拓展插件
## burpsuit拓展插件
- https://github.com/PortSwigger    --burpsuite官方插件库。商业版。
- https://github.com/lilifengcode/Burpsuite-Plugins-Usage    --burp插件使用介绍
- https://github.com/snoopysecurity/awesome-burp-extensions    --awesome系列之burp拓展
- https://github.com/alphaSeclab/awesome-burp-suite    --Awesome Burp Suite Resources. 400+ open source Burp plugins, 500+ posts and videos.
### burp功能增强
- https://github.com/c0ny1/sqlmap4burp-plus-plus    --sqlmap4burp++跨平台Burp与sqlmap联动插件
- https://github.com/d3vilbug/HackBar    --hackbar
- https://github.com/bit4woo/knife    --Brup右键菜单增强
- https://github.com/bit4woo/domain_hunter_pro    --目标管理、信息搜集、工具联动。testjob。
- https://github.com/projectdiscovery/nuclei-burp-plugin    --联动nuclei一键生成poc
### burp协议分析
- https://github.com/mr-m0nst3r/Burpy    --Web端JS加密算法调试解密
- https://github.com/c0ny1/jsEncrypter    --Web前端加密协议Fuzz爆破
- https://github.com/gh0stkey/CaA    --流量收集与分析
### burp防护绕过
- https://github.com/TheKingOfDuck/burpFakeIP    --Py。IP修改伪造。
- https://github.com/RhinoSecurityLabs/IPRotate_Burp_Extension/    --Py。使用AWS API Gateway在每个请求上更改IP访问。
- https://github.com/nccgroup/BurpSuiteHTTPSmuggler    --使用几种技巧绕过WAF。
- https://github.com/c0ny1/chunked-coding-converter    --用于http传送过程的分块技术，可绕WAF等防护设备。
- https://github.com/0xC01DF00D/Collabfiltrator    --利用DNS传输远程代码执行结果。
### Burp敏感信息
- https://github.com/m4ll0k/BurpSuite-Secret_Finder    --在http请求中扫描 api key/tokens
- https://github.com/modzero/interestingFileScanner    --增强敏感文件扫描
### burp漏洞扫描
- https://github.com/ilmila/J2EEScan    --70多个Java Web应用的漏洞测试
- https://github.com/nccgroup/argumentinjectionhammer    --识别参数注入漏洞
- https://github.com/portswigger/http-request-smuggler    --http请求走私。
- https://github.com/yandex/burp-molly-pack    --XXE SSRF漏洞利用。
- https://github.com/ethicalhackingplayground/ssrf-king    --ssrf漏洞扫描

## Cobaltstrike拓展插件
- https://www.cobaltstrike.com/aggressor-script/index.html    --脱离MSF之后的Aggressor Script 成为了开源脚本引擎 Cortana 的接班人
- https://bbs.ichunqiu.com/thread-53015-1-1.html    --[思路/技术] Cobaltstrike系列教程(十)安装扩展。
- https://wbglil.gitbook.io/cobalt-strike    --Cobaltstrike基础，进阶，原理。
- https://github.com/dcsync/pycobalt    --Py3。Python API for Cobalt Strike
- https://pingmaoer.github.io/2020/06/24/CobaltStrike二次开发环境准备/    --RedCore红队学院CSTips
- https://github.com/verctor/CS_xor64    --Java。生成cobaltstrike破解版所需的`xor64.bin`。
- https://github.com/Twi1ight/CSAgent/    --Java。Cobaltstrike汉化加载器。
### cobalt strike插件集合
- https://github.com/harleyQu1nn/AggressorScripts/    --CS收集脚本介绍
- https://github.com/rsmudge/cortana-scripts    --Java。作者用于cs2.x与armitage的可拓展插件，cs3.x后为AggressorScripts。
- https://mp.weixin.qq.com/s/CEI1XYkq2PZmYsP0DRU7jg    --公众号：使用Aggressor脚本雕饰Cobalt Strike
- https://github.com/FortyNorthSecurity/AggressorAssessor    --cs3.x脚本收集
- https://github.com/Al1ex/CSPlugins    --Cobaltstrike第三方插件收集
- https://github.com/z1un/Z1-AggressorScripts    --工具集汇总
- https://github.com/Ridter/CS_Chinese_support/    --Cobalt Strike3.0传输信息的汉化插件。
### cobaltstrike服务检测
- https://github.com/whickey-r7/grab_beacon_config    --NSE。nmap扫描CS后门beacon。
### cobaltstrike免杀
- https://github.com/Mr-Un1k0d3r/SCT-obfuscator    --Cobalt Strike SCT有效载荷混淆器
- https://github.com/rvrsh3ll/CPLResourceRunner    --Py。提取`beacon.bin`文件的shellcode。
- https://github.com/search?l=Batchfile&o=desc&q=signtool+sign+pfx&s=indexed&type=Code    --使用第三方证书签名。
- https://github.com/RCStep/CSSG    --Shellcode生成工具
### cobaltstrike通讯
- https://blog.csdn.net/qq_27446553/article/details/79380021    --邮件上线提醒。
- https://github.com/mdsecactivebreach/CACTUSTORCH    --CDN域前置隐匿技术
- https://xz.aliyun.com/t/5728/    --反溯源-cs和msf域名前置上线。公众号:DNS上线CS(反溯源);--
- https://github.com/Mr-Un1k0d3r/CatMyFish    --搜索分类域，为Cobalt Strike beacon C&C设置白名单域
- https://github.com/threatexpress/malleable-c2    --利用jquery文件进行C2通讯，在文件内做了JS混淆绕过防火墙
- https://github.com/Und3rf10w/external_c2_framework    --Py。Cobalt Strike's External C2构造CS的通讯通道。
- https://www.cobaltstrike.com/help-malleable-c2    --Malleable C2 Profiles，配置C2-profile文件生成个人`cobaltstrike.store`文件绕过流量检测
- https://github.com/ryhanson/ExternalC2    --一个用于将通信渠道与Cobalt Strike External C2服务器集成的库
- https://github.com/threatexpress/cs2modrewrite    --用于将Cobalt Strike配置文件转换为mod_rewrite脚本的工具
### cobaltstrike信息搜集
- https://github.com/pxss/navicatpwd    --Cobalt Strike Navicate解密脚本
- https://github.com/outflanknl/Ps-Tools    --cobaltstrike插件。高级进程监控组件。goodjob
### cobaltstrike攻击拓展
- https://github.com/DeEpinGh0st/Erebus    --权限维持、横向拓展、本地提权、痕迹清理。G:/pandasec888/taowu-cobalt-strike --梼杌;--
- https://github.com/killswitch-GUI/CobaltStrike-ToolKit    --AD域控利用脚本集。
- https://github.com/gloxec/CrossC2/tree/master/src    --cobaltstrike插件。生成CobaltStrike的跨平台beacon。goodjob。G:/mirrors_trending/CrossC;--
- https://github.com/darkr4y/geacon    --Go。OSX、Linux系统beacon上线。goodjob。
- https://github.com/Rvn0xsy/Cobaltstrike-atexec    --C++。利用Windows远程访问工具（WMIEXEC,PSEXEC,SMBEXEC, ATEXEC）其一的任务计划进行横向，需要与135端口、445端口进行通信。
- https://github.com/m0ngo0se/Peinject_dll    --使用shellexecute函数感染正常文件PE。testjob。
### cobaltstrike漏洞利用
- https://github.com/phink-team/Cobaltstrike-MS17-010    --cobaltstrike ms17-010（win7 x64 and win2008 r2）等插件
- https://github.com/rsmudge/ElevateKit/    --PS。CS利用第三方模块提权。cna插件。
- https://github.com/Rvn0xsy/CVE_2020_0796_CNA    --SMBv3 LPE Exploit
- https://github.com/rxwx/spoolsystem    --利用漏洞欺骗打印机进行提权
- https://github.com/dtmsecurity/bof_helper    --Py3。BOF编写辅助器。
### cobaltstrike痕迹清理
- https://github.com/QAX-A-Team/EventLogMaster    --RDP日志取证&清除。

## 端口扫描拓展插件
- https://github.com/johnnyxmas/scancannon    --Bash。联动masscan和nmap。
### Nmap相关工具
- https://raw.githubusercontent.com/nmap/nmap/master/nmap-service-probes    --Nmap指纹库，资产识别指针、配置文件。greatjob。
- https://xz.aliyun.com/t/6002    --如何修改nmap，重新编译，绕过IDS流量检测。G:/al0ne/Nmap_Bypass_IDS;--
- https://github.com/Ullaakut/nmap    --Go。Nmap调用库go
- https://github.com/savon-noir/python-libnmap    --Py。nmap调用库python
- https://github.com/cldrn/nmap-nse-scripts    --NSE收集列表
- https://github.com/vulnersCom/nmap-vulners    --使用nmap扫描常见的服务漏洞
- https://github.com/m4ll0k/AutoNSE    --NSE自动化利用
- https://github.com/vulnersCom/nmap-vulners    --Lua。NSE利用 Vulners.com API将相关漏洞信息评分返回
- https://github.com/Rvn0xsy/nse_vuln    --Nmap扫描漏洞利用脚本。tomcat任意文件上传漏洞CVE-2017-12615、weblogic、http（CVE-2017-12615/CNVD-C-2019-4814/CVE-2018-2894）
- https://github.com/Screetsec/Dracnmap    --Bash。将Nmap复杂的命令进行一定程度的集成与简化，使新用户更加容易上手。
- https://github.com/cldrn/rainmap-lite    --DjanGo。Web版Nmap，可以建立新的扫描服务器，允许用户从他们的手机/平板电脑/网络浏览器启动Nmap扫描
- https://github.com/trimstray/sandmap    --Bash。linux下Nmap可配置形式的命令行操作台
- https://github.com/scipag/vulscan    --基于nmap的高级漏洞扫描器，命令行环境使用
- https://github.com/Rev3rseSecurity/WebMap    --将nmap的xml web展示器
- https://github.com/m0nad/HellRaiser    --基于nmap的扫描器，与cve漏洞关联。
- https://github.com/ernw/nmap-parse-output    --nmap报告解析器。G:/materaj/nmap-parser-xml-to-csv;--
- https://github.com/DanMcInerney/msf-autopwn    --执行NMap扫描或读取扫描结果， 然后自动使用msf攻击包含常见漏洞的主机
- https://github.com/rootlabs/nWatch    --联动nmap并对组织内网进行扫描
- https://github.com/Yukinoshita47/Yuki-Chan-The-Auto-Pentest    --集成子域名枚举、nmap、waf指纹识别等模块的web应用扫描器
- https://github.com/ring04h/wyportmap    --调用nmap目标端口扫描+系统服务指纹识别
- https://github.com/cloudflare/flan    --Py。cloudflare基于nmap开发的漏洞检测工具
### Masscan相关工具
- https://github.com/knownsec/ksubdomain    --Go。与网卡直接交互无状态子域名爆破
- https://github.com/offensive-security/masscan-web-ui/    --PHP。Masscan WebGui。

## Kali系统拓展插件
- https://github.com/Jack-Liang/kalitools/    --Kali Linux工具文档翻译，汉化kali
- https://github.com/secforce/sparta    --Py。界面化，联动Nmap、Nikto、Hydra等工具
- https://github.com/skavngr/rapidscan    --Py3。simple，联动kali下工具，漏洞扫描工具
- https://github.com/baguswiratmaadi/reverie    --Bash。ParrotSecOs联动工具。
- https://github.com/koenbuyens/kalirouter    --将kali设置为一个路由流量分析系统
## Nessus拓展插件
- https://github.com/se55i0n/Awvs_Nessus_Scanner_API    --扫描器Awvs 11和Nessus 7 Api利用脚本
- https://github.com/DanMcInerney/msf-autoshell    --配合nessus扫描结果进行msf攻击
- https://github.com/MooseDojo/apt2    --联动nmap、nessus等工具进行安全测试
## AWVS拓展插件
- awvs下载    --fahai.org;--
- https://www.52pojie.cn/thread-214819-1-1.html    --awvs10.5开发框架破解版。商业版。
- https://github.com/l3m0n/awvs_190703137    --Py。Linux版awvs
- https://github.com/x364e3ab6/AWVS-13-SCAN-PLUS    --AWVS桌面版。
- https://github.com/gatlindada/awvs-decode/    --15行代码解码awvs插件解密。G:/fnmsd/awvs_script_decode;
- https://github.com/NS-Sp4ce/AWVS11.X-Chinese-Version    --JS。awvs11汉化包
- https://github.com/grayddq/PublicSecScan    --Py。调用awvsAPI对WEB资产进行分布式WEB安全扫描
## Sqlmap拓展插件
- https://github.com/codewatchorg/sqlipy    --burp与sqlmap联动插件
- https://github.com/RicterZ/websocket-injection    --Py3。WebSocket 中转注入工具
- https://github.com/Hood3dRob1n/SQLMAP-Web-GUI    --PHP。sqlmap的web gui
- https://github.com/KINGSABRI/sqlmap-tamper-api    --利用各种语言来编写sqlmapTamper
- https://github.com/0xbug/SQLiScanner    --一款基于sqlmapapi和Charles（青花瓷）的被动SQL注入漏洞扫描工具
- https://github.com/fengxuangit/Fox-scan    --基于sqlmapapi的主动和被动资源发现的漏洞扫描工具
- https://github.com/UltimateHackers/sqlmate    --在sqlmap基础上增加了目录扫描、hash爆破等功能
- https://github.com/ysrc/GourdScanV2    --ysrc出品的被动式漏洞扫描工具，基于sqlmapapi
- https://github.com/zt2/sqli-hunter    --基于sqlmapapi，ruby编写的漏洞代理型检测工具
- https://github.com/jesuiscamille/AutoSQLi    --利用DorkNet，Googler， Ddgr， WhatWaf 和 sqlmap自动注入
- 公众号：记一次渗透棋牌APP实录    --利用sqlmap --technique S --os-shell栈查询(stack queries)进行命令执行
## Metasploit拓展插件
- https://github.com/13o-bbr-bbq/machine_learning_security/tree/master/DeepExploit    --结合机器学习与msf的全自动测试工具
- https://github.com/r00t-3xp10it/Meterpreter_Paranoid_Mode-SSL    --一个可以创建SSL/TLS shell连接的脚本
- https://github.com/DanMcInerney/msf-netpwn    --等待msf的session，并自动提为域管理
- https://github.com/NullArray/AutoSploit    --利用Shodan API搜索引擎收集目标， 并自动调用设定的msf模块对目标发动攻击
- https://github.com/WazeHell/metateta    --使用msf脚本，根据特定协议进行扫描
- https://github.com/fbkcs/msf-elf-in-memory-execution    --Metasploit模块， 用于在内存中执行ELF文件
- https://github.com/ElevenPaths/Eternalblue-Doublepulsar-Metasploit    --metasploit双星攻击利用文件
- https://github.com/darkoperator/Metasploit-Plugins    --msf扩展资产搜集与帮助插件
- https://github.com/D4Vinci/One-Lin3r    --metasploit、payload辅助查询工具
- https://github.com/shizzz477/msploitego    --将msf数据库与maltego进行图形化展示
- https://github.com/scriptjunkie/msfgui    --Java。metasploit的界面GUI，强化Windows下支持。Noupdate。Goodjob。
- https://www.yuque.com/funnywolfdoc/viperdoc    --基于Django的MSF图形界面、执行模块、汉化分类。社区版加特林。G:/FunnyWolf/Viper;--
- https://github.com/Zerx0r/Kage    --VueJS。图形化MSF、Session Handler控制。界面GUI。goodjob。
- https://github.com/0x727/MetasploitCoop_0x727    --Vue,Python。基于msf的后渗透协作平台
## Empire拓展插件
- https://paper.tuisec.win/detail/f3dce68a0b4baaa    --利用Empire获取域控权限
- https://github.com    --empire的web界面
- https://github.com/byt3bl33d3r/DeathStar    --Py3。调用Empire RESTful API 自动化获取域管权限的
- https://byt3bl33d3r.github.io/automating-the-empire-with-the-death-star-getting-domain-admin-with-a-push-of-a-button.html    --DeathStar教程
- https://github.com/infosecn1nja/e2modrewrite    --用于将Empire配置文件转换为Apache modrewrite脚本
## 菜刀拓展插件
- https://github.com/AntSword-Store/    --中国蚁剑插件市场
- https://paper.seebug.org/1565/    --As-Exploits: 中国蚁剑后渗透框架。G:/yzddmr6/As-Exploits;--
- https://github.com/yzddmr6/as_webshell_venom    --js。免杀webshell无限生成工具蚁剑版
- https://github.com/Ch1ngg/CaidaoMitmProxy    --Py3。基于HTTP代理中转菜刀过WAF,基于菜刀20160622版本修改和测试。
- https://github.com/ekgg/Caidao-AES-Version    --Burp插件。用AES算法透明加密菜刀的http数据流