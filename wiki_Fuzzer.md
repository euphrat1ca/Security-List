# 漏洞挖掘分析
- https://github.com/ngalongc/bug-bounty-reference    --漏洞挖掘write-up
- https://github.com/1hack0/bug-bounty-101    --挖洞技术手册
- https://github.com/writeups/ios    --ios漏洞writeup笔记
- https://github.com/userlandkernel/plataoplomo    --Sem Voigtländer 公开其发现的 iOS 中各种漏洞，包括（Writeup/POC/Exploit）
- https://github.com/Ivan1ee/NET-Deserialize    --.Net反序列化漏洞
- https://github.com/SCUBSRGroup/Automatic-Exploit-Generation    --自动化软件漏洞发掘
- https://blog.ripstech.com/filter/vulnerabilities/    --Bitbucket是Atlassian开发的版本控制软件与漏洞挖掘教程
# Fuzzing模糊测试
- https://google.github.io/fuzzbench/    --谷歌模糊测试测评工具，竞品比对
- https://www.isasecure.org/en-US/    --工控模糊测试。edsa认证。P:Wurldtech Achilles 阿基里斯认证;--
- LLVM工具链，基于编译器插桩的coverage-feedback driven fuzzer
- https://mp.weixin.qq.com/s/nREiT1Uj25igCMWu1kta9g    --Fuzzing战争: 从刀剑弓斧到星球大战。 Flanker论安全
- https://github.com/HexHive/FuzzGen/    --C++。根据库的接口I/O自动生成fuzzer
## 模糊测试资源
- http://www.freebuf.com/articles/rookie/169413.html    --一系列用于Fuzzing学习的资源汇总
- https://github.com/secfigo/Awesome-Fuzzing    --Fuzzing模糊测试相关学习资料
- https://github.com/fuzzdb-project/fuzzdb    --fuzz资料数据库
- https://github.com/raminfp/linux_exploit_development    --linux漏洞利用开发手册
- https://github.com/mozillasecurity/fuzzdata    --模糊测试输入样本资源。
- https://www.fuzzysecurity.com/tutorials.html    --fuzzysecurity教程。"*egghunter"。
## 模糊测试利用
- https://google.github.io/clusterfuzz/    --谷歌集群模糊测试平台
- https://github.com/google/AFL    --American Fuzzy Lop 以代码覆盖率作为变异策略的fuzz，符合测试和其无数衍生工具。
- http://zeroyu.xyz/2019/05/15/how-to-use-afl-fuzz/    --Intro。AFL使用指南。
- https://github.com/google/oss-fuzz    --C。谷歌对开源项目的进行免费的模糊测试服务
- https://github.com/bunzen/pySSDeep    --Py。一个基于模糊哈希（Fuzzy Hashing）算法的工具。G:/glaslos/ssdeep;G:/ssdeep-project/ssdeep;--
### 文件模糊测试
- https://github.com/googleprojectzero/Jackalope    --C++。基于覆盖率指导的Windows macOS的二进制模糊工具。
- https://github.com/uds-se/FormatFuzzer    --Py。基于010 Editor 文件格式模板的多文件测试工具。
### 系统模糊测试
- https://github.com/mxmssh/drAFL    --C。Linux系统模糊测试。G:/atrosinenko/kbdysch;G:/google/oss-fuzz;--
- https://github.com/googleprojectzero/winafl    --C。Google Project Zero 基于Windows AFL开发的模糊测试框架。P:阿尔法实验室-AFL漏洞挖掘技术漫谈;--
### 固件模糊测试
- https://github.com/qilingframework/qiling    --Py3。基于Unicorn进行固件模拟Qiling Unicornalf IOT模糊测试。
- https://github.com/zyw-200/FirmAFL    --C。针对iot固件IoT firmware灰盒模糊测试，覆盖Firmadyne数据库中90.2%的固件，支持mipsel、mipseb和armel三种CPU架构。welljob。P:p2im;P:Hal-fuzz;--
- https://github.com/k0keoyo/kDriver-Fuzzer    --C。基于ioctlbf框架编写的驱动漏洞挖掘工具kDriver Fuzzer。
### 软件模糊测试
- https://github.com/google/honggfuzz    --C。具有反馈驱动（Feedback-Driven）的持续性软件代码测试。2k。
- https://github.com/dzzie/COMRaider    --客户端溢出风险测试
- http://blog.topsec.com.cn/alphafuzzer/    --阿尔法实验室文件模糊测试工具。
- https://github.com/google/atheris    --python代码模糊测试
### Web应用模糊测试
- https://github.com/xmendez/wfuzz    --Py。Web安全模糊测试工具，owasp常见漏洞，可处理burp所抓请求和响应报文。goodjob。G:/ffuf/ffuf;--
- https://github.com/1N3/BlackWidow    --Py。利用爬虫收集目标网站的情报信息并对 OWASP 漏洞进行模糊测试。
- https://bbs.ichunqiu.com/thread-24898-1-1.html    --Test404 -HTTP Fuzzer V3.0
- https://github.com/floyd-fuh/afl-cgi-wrapper    --利用AFL fuzz web CGI
### 协议模糊测试
- https://www.peach.tech/    --C#。Peach3模板流（通过提前定义好的xml等文件模板对目标单位进行测试）模糊测试，网络协议、API、文件格式模糊测试。
- https://github.com/MozillaSecurity/peach    --Py3。MozPeach是Peach v2.7的一个分支，由Mozilla Security维护。
- https://mp.weixin.qq.com/s/yYkbysywQXD5l-SS0jQ3_A    --公众号：使用Peach进行模糊测试从入门到放弃。G:/TideSec/Peach_Fuzzing;P:/【工控安全】基于Peach的Modbus协议模糊测试;--
- https://github.com/bl4ckic3/Modbus-Fuzzer    --Py2。Modbus协议模糊测试工具。
- https://github.com/cisco-sas/kitty    --Py。针对TCP/IP的模糊测试框架。goodjob。
- https://kitty.readthedocs.io/en/latest/    --Intro。Python类库kittyfuzzer使用手册
- https://github.com/cisco-sas/katnip    --Py。kitty框架拓展库。
- https://paper.seebug.org/772/    --techteach。如何使用 KittyFuzzer 结合 ISF 中的工控协议组件对工控协议进行 Fuzz。
- https://github.com/jtpereyda/boofuzz    --Py。基于OpenRCE/sulley框架二次开发的网络协议fuzz测试。G:/OpenRCE/sulley;G:/aflnet/aflnet;--
- https://github.com/Cisco-Talos/mutiny-fuzzer    --Py。MikroTik基于pcap包解析的网络协议模糊测试。

## 自动化测试
- http://bbs.anjian.com/    --按键精灵。G:/taojy123/KeymouseGo;--
- https://pypi.org/project/pynput/    --python操作键盘库
- https://github.com/sleepybear1113/taobaoVisitingVenues    --js。双十一活动自动化地操作淘宝浏览店铺得喵币脚本 for Androidz。
- https://github.com/microsoft/playwright-python    --Python自动化测试工具，支持JavaScript（TypeScript）、Python、C#和Go语言，支持有头（headful）模式和无头（headless）模式运行。G:/Gerapy/GerapyPlaywright;--
### 质量测试
1. https://github.com/hellodigua/code996    --Ts。统计 Git 项目的 commit 时间分布，进而推导出项目的编码工作强度 代码996
### 爬虫采集框架
- https://github.com/s-rah/onionscan    --darkweb暗网爬虫
- https://github.com/alphardex/looter    --轻量型爬虫框架，类比Scrapy
- https://github.com/luyishisi/Anti-Anti-Spider    --反爬虫防护绕过
- https://github.com/CharlesPikachu/DecryptLogin    --网站模拟登陆
- https://github.com/CriseLYJ/awesome-python-login-model    --Py。基于selenium网站登录
- https://github.com/Maicius/InterestingCrawler    --抓取QQ空间说说内容并进行分析
- https://github.com/xchaoinfo/fuck-login    --模拟登录网站，停止维护
- https://github.com/xjr7670/QQzone_crawler    --QQ 空间动态爬虫，利用cookie登录获取所有可访问好友空间的动态保存到本地
- https://github.com/tikazyq/crawlab    --Py3。分布式任务管理爬虫，漏洞预警系统设计。
- https://github.com/zorlan/skycaiji/    --php。全自动蓝天采集器。
- https://github.com/kangvcar/InfoSpider    --Py3。爬虫工具箱，针对使用者所拥有的众多数据源进行数据搜集。
- https://github.com/chaitin/rad    --xray配套Rad爬虫，带有无头浏览器登录录制。goodjob。G:/0Kee-Team/crawlergo;G:/jaeles-project/gospider;--
- https://www.anquanke.com/post/id/178339    --漏扫动态爬虫实践。G:pyppeteer 无头浏览器;G:Chromedp;--
### 浏览器模拟
- https://github.com/SeleniumHQ/selenium    --Web headless无头浏览器自动化测试。
- https://github.com/xuyichenmo/selenium-document    --Selenium的中文文档。
- https://www.chromium.org/    --Chrome内核，无头浏览器。G:/ariya/phantomjs/;W:miniblink.net;--
### 移动端测试
- https://github.com/Genymobile/scrcpy    --C。基于adb通过 USB (或 TCP/IP) 连接的安卓设备，且不需要任何 root 权限，支持 GNU/Linux、Windows 和 macOS。
- https://github.com/AirtestProject/Airtest    --Py。网易Android、iOS跨平台的UI自动化框架。
- https://github.com/hyb1996/Auto.js    --js。安卓平台上的JavaScript自动化工具。
- http://appium.io/    --iOS、Android自动化测试。UIAutomation、XCTest、KIF等。
- https://github.com/liriliri/eruda    --JS。移动网页前端开发调试工具。G:/Tencent/vConsole;--
- https://docs.hamibot.com/    --Auto.js。Android 平台 JavaScript 自动化工具，群控脚本。G:/hamibot/hamibot;--

## 压测泛洪
- https://github.com/ywjt/Dshield    --Py。DDOS防护。
### 协议流量压测
- http://www.yykkll.com    --压力测试站评测。W:defconpro.net;W:vip-boot.xyz;--
- https://rocketstresser.com/login.php    --多协议在线压测，支持cdn测试。
- https://github.com/wenfengshi/ddos-dos-tools    --压力测试工具集
- https://github.com/wenfengshi/ddos-dos-tools    --压力测试工具集
- https://tools.kali.org/information-gathering/hping3    --HPing3网络工具组包。P:LOIC;P:核武器CC-穿盾版;P:天降激光炮315;P:hyenae;--
- https://github.com/Markus-Go/bonesi    --C。模拟僵尸网络进行ICMP/UDP/TCP/HTTP压测
- https://github.com/IKende/Beetle.DT    --C#。分布式压力测试工具
- https://github.com/wg/wrk    --C。http流量测试。
- https://github.com/mschwager/dhcpwn    --Py。DHCP/IP压力测试。
- https://github.com/Microsoft/Ethr    --Go。跨平台，TCP， UDP， HTTP， HTTPS压力测试工具
- https://github.com/loadimpact/k6    --GO Javascript组件进行负载测试。goodjob。
- https://github.com/NewEraCracker/LOIC/    --C#,Mono。基于Praetox's LOIC project的压测工具。
- https://github.com/649/Memcrashed-DDoS-Exploit    --Py。利用shodan搜索Memcached服务器进行压力测试。
### 拒绝服务压测
- https://github.com/ajmwagar/lor-axe    --Rust。多线程、低带宽消耗的HTTP DoS工具。G:/JuxhinDB/synner;--
- https://github.com/jseidl/GoldenEye    --Py。DOS攻击测试
- https://github.com/jagracey/Regex-DoS    --RegEx拒绝服务扫描器
- https://github.com/doyensec/regexploit    --分析正则表达式，寻找ReDoS漏洞
- https://github.com/algo7/bluekeep_CVE-2019-0708_poc_to_exploit    --Py。RDP服务远程命令执行/DOS攻击/蓝屏exp。
- https://xz.aliyun.com/t/7895/    --techteach。利用WAF进行拒绝服务攻击。利用自动加载图片等资源文件的特性。
- https://www.freebuf.com/column/201766.html    --techteach。正则表达式所引发的DoS攻击（Redos）。G:/superhuman/rxxr2;--
- https://github.com/EZLippi/WebBench    --C。DDOS网站压力测试，最高并发3万
- https://www.cuijianxiong.top/2021/03/30/暴力的攻击Dos/    --大数精度计算BigDecimal、正则匹配资源耗尽。