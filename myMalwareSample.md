# myMalwareSample
 MalwareSample
- https://github.com/chenerlich/FCL    恶意代码使用的命令行收集
- https://paper.seebug.org/421    常见软件合集与恶意软件分析
- https://github.com/sapphirex00/Threat-Hunting    apt恶意软件样本
- https://www.malware-traffic-analysis.net/    恶意软件样本
- http://dasmalwerk.eu/    恶意软件样本
- https://lolbas-project.github.io/   #
- https://github.com/ytisf/theZoo    恶意软件样本
- https://github.com/mstfknn/malware-sample-library    恶意软件样本
- http://99.248.235.4/Library/    恶意软件样本库。ladder
- https://www.connect-trojan.net    恶意软件搜集，查找测试工具
- https://github.com/robbyFux/Ragpicker    恶意软件信息爬取汇总分析
- https://github.com/phage-nz/ph0neutria    恶意软件信息爬取汇总分析
- https://github.com/JR0driguezB/malware_configs    常见恶意配置文件

以下来自于公众号：熊猫正正 安全分析与研究 （偷懒就不排版了）
如果你身在安全公司，有客户端类的安全产品，一般从下几个渠道可以获取：  
(1)一些客户端收集用户的样本，然后保存到样本TOP库，从黑灰库中找可疑样本进行分析，说不定就可以找到惊喜  
(2)用户反馈的一些样本，或你帮用户解决安全问题自己从用户电脑上收集回来的样本  
(3)有些公司会有一些安全论坛，用户也会上传一些样本到论坛上，定期去查看分析  
(4)如果公司有VT帐号，可以从VT上去下载相关的样本  
(5)可以从内部的一些监控系统爬虫系统中找到新的样本或变种样本  
如果没有客户端产品，一般都是从客户反馈收集的样本进行分析处理，或者从一些开源的样本下载网站，以及与其它公司购买交换而来
  
如果你不在安全公司工作，可以从以下几个渠道获取：  
(1)国外样本分享网站，如：  
http://contagiodump.blogspot.com 
(2)Github上去搜malware， 如：https://github.com/rshipp/awesome-malware-analysis （你可以找到很多想要的）  
(3)加入Google Malware邮件组或一些TG组，里面会有人分享样本，如：mobilemalware@googlegroups.com  
(4)关注一些国外安全研究人员的Twitter，每天都会分享很多新的变种样本  
(5)关注一些国外大的安全公司的博客，如：
http://researchcenter.paloaltonetworks.com
https://www.fireeye.com/blog.html
http://www.symantec.com/connect/blogs
https://blog.kaspersky.com
http://cybersecurityminute.com/security-blogs/source/Trend+Micro+Blog/
这上面会定期更新一些恶意样本的分析报告，有时候会放样本，没有样本可以通过HASH自己Google去找
(6)国内一些安全论坛以及安全媒体，也会有很多人上传一些样本，如看雪，卡饭，吾爱破解，FreeBuf等
(7)国内一些安全公司的论坛，不知道还有几个在持续运营了。。。。如：360杀毒论坛，金山杀毒论坛，电脑管家论坛，瑞星杀毒论坛等
(8)如果你有钱任性，完全可以自己去买个VT帐号，里面的样本你这辈子都分析不完
下面给大家分享一些在线或开源沙箱以及一些流行样本下载链接，大部分的在线沙箱都支持下载样本，不过有些是免费的，有些需要注册，有些是收费的，有些需要积分等等
1.theZoo
https://github.com/ytisf/theZoo
2.contagio
http://contagiodump.blogspot.com/
The password scheme is infected666 followed by the last character before the zip extension. e.g abc.zip will have the password infected666c.
3.Hybrid Analysis
https://www.hybrid-analysis.com/
4.AVCaesar
https://avcaesar.malware.lu/
5.Das Malwerk
https://dasmalwerk.eu/
6.KernelMode.info
https://www.kernelmode.info/forum/viewforum.php?f=16
7.MalShare
https://malshare.com/
8.VirusBay
https://beta.virusbay.io/
9.Virusign
http://www.virusign.com/
10.VirusShare
https://virusshare.com/
11.Malwarebytes Research Center
https://forums.malwarebytes.com/forum/44-research-center/
12.Mobile Malware (Google Group)
https://groups.google.com/forum/#!forum/mobilemalware
13.SARVAM
http://sarvam.ece.ucsb.edu/recent
14.Malc0de
http://malc0de.com/database/
15.VX Vault
http://vxvault.net/ViriList.php
16.ThreatBook
https://s.threatbook.cn/
17.Intezer Analyze
https://analyze.intezer.com
18.CAPE Sandbox
https://cape.contextis.com/
19.Joe Sandbox
https://www.joesandbox.com/
20.AppAnyRun
https://app.any.run/
21.VMRay
https://www.vmray.com/
22.VirusTotal
https://www.virustotal.com
23.Linux开源沙箱
https://github.com/monnappa22/Limon
24.anlyz
https://sandbox.anlyz.io
25.cryptam
http://www.cryptam.com
26.cuckoo
https://cuckoosandbox.org/
27.detux
https://github.com/detuxsandbox/detux/
28.drakvuf
https://drakvuf.com/
29.threatbook
30.firmware
http://firmware.re/
31.virusscan
https://virusscan.jotti.org/en
32.malheur
https://github.com/rieck/malheur
33.malwr
https://malwr.com/
Android Samples
1.Koodous
https://koodous.com/
2.AndroMalShare
http://sanddroid.xjtu.edu.cn:8080/
3.Android-Malware(Github)
https://github.com/ashishb/android-malware
4.App Sandbox
https://app.sndbox.com
5.AndroidMalware_2019
https://github.com/sk3ptre/AndroidMalware_2019
OSX Samples
1.Objective-See Mac Malware
https://objective-see.com/malware.html
2.Manwe MAC Malware Samples
https://macmalware.manwe.io/
Linux Samples
1.Linux Sandbox
https://linux.huntingmalware.com/analysis/
2.Detux-The Linux Sandbox
https://github.com/detuxsandbox/detux
https://detux.org/index.php
恶意样本下载网站
https://github.com/InQuest/malware-samples