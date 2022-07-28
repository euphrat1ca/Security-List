# 数字取证
- http://xlysoft.net/    --SalvationDATA（效率源）取证工具。P:ios盘古;--
- https://github.com/alphaSeclab/awesome-forensics    --取证相关工具和文章。收集的所有开源工具: sec-tool-list;逆向资源: awesome-reverse-engineering;网络相关的安全资源: awesome-network-stuff;攻击性网络安全资源: awesome-cyber-security;开源远控和恶意远控分析报告: awesome-rat;Webshell工具和分析/使用文章: awesome-webshell;--
- https://github.com/laramies/metagoofil    --Py。从文件获取相关网站的用户名与邮箱等数据。documents (pdf,doc,xls,ppt,etc).
- https://github.com/mozilla/mig    --go。火狐mozilla基金会针对海量文件的内容定位工具，支持节点分级部署。Deprecation。
- https://polytechnic.purdue.edu/facilities/cybersecurity-forensics-lab/tools    --FileTSAR大规模的数据调查取证。
- https://techtalk.gfi.com/top-20-free-digital-forensic-investigation-tools-for-sysadmins/    --翻译|系统管理员免费数字取证调查工具TOP20。
- https://0xrick.github.io/lists/stego/    --隐写术工具和资源列表 Steganography - A list of useful tools and resources。
## 文件取证
- http://qpdf.sourceforge.net/    --查看pdf文件并整理提取信息
- http://zipinfo.com/    --在无需提取的情况下列出了zip文件的内容信息
- https://github.com/ElevenPaths/FOCA    --文档中查找元数据和隐藏信息
### 图片取证
- https://www.freebuf.com/sectool/208781.html    --将任意文本隐藏在音频视频图片和文本中的多种方式。
- https://github.com/DominicBreuker/stego-toolkit    --图片、音频隐写工具集。P:Stegosuite;--
- https://github.com/redaelli/imago-forensics    --Py3。将照片中Exif、MIME等信息提取存入CSV/sqlite中
- http://www.magicexif.com/    --将照片图像中的exif信息数据化
- http://mediaarea.net/MediaInfo    --类似于exiftool来查看内容区域和元数据信息
- https://www.sno.phy.queensu.ca/~phil/exiftool/    --检查图像文件的exif元数据
- https://www.gimp.org/    --Gimp可将各类图像文件转换为可视化数据，用于确认文件是否是一个图像文件。
- https://github.com/GuidoBartoli/sherloq    --C++。数字图片取证。
- https://github.com/livz/cloacked-pixel    --Py3。LSB图片数据隐藏
- http://www.caesum.com/handbook/Stegsolve.jar    --Java。图片隐写查看器，多图层查看器。
- http://www.libpng.org/pub/png/apps/pngcheck.html    --图片检测。goodjob。
- https://github.com/xerohackcom/Chaya    --Py3。基于LSB-LPS技术图像隐写。WellJob。
### 音频取证
- https://embeddedsw.net/OpenPuff_Steganography_Home.html    --图片音视频隐写，加密工具。


## 资产设备取证
- https://www.x-ways.net/winhex/    --Winhex是一款的十六进制编辑器，在计算机取证，数据恢复，低级数据处理。
- http://www.sweetscape.com/010editor/    --识别不同文件格式（模板）的16进制编辑器，具有文件修复功能。G:/WerWolv/ImHex;--
- https://www.cgsecurity.org/wiki/TestDisk    --磁盘分区修复。
- https://github.com/google/bochspwn-reloaded    --Bochspwn Reloaded（内核信息泄漏检测）工具
- https://www.nirsoft.net/utils/usb_log_view.html    --USB设备监控软件，支持后台运行，USBLogView可以记录插入或拔出系统的任何USB的详情信息。
## 工业系统取证
- https://www.freebuf.com/articles/ics-articles/253382.html    --ICS领域数字取证技术，工控取证。P:橡树岭国家实验室 网络安全小组;--
## Windows取证
- https://www.microsoft.com/zh-cn/p/app/9n26s50ln705/    --Windows File Recovery微软文件恢复，windows 10 restore lost files恢复格式化或者损坏的硬盘。
- https://www.ontrack.com/products/data-recovery-software/    --EasyRecovery文件恢复软件。商业版。易我数据恢复;RECUVA;--
- http://www.diskgenius.cn/    --数据还原/分区管理/备份还原。商业版。
- https://clonezilla.org/downloads.php    --再生龙(Clonezilla)是一个免费的灾难恢复、硬盘克隆、硬盘映像档制作的部署和解决方案，由台湾的国家高速网络与计算中心(国网中心)所开发。
- https://zhuanlan.zhihu.com/p/453030502    --Macrium Reflect 磁盘克隆 uefi引导 diskpart删除health recovery进行磁盘恢复。
- https://github.com/SekoiaLab/Fastir_Collector    --Windows取证/信息收集，不限于内存，注册表，文件信息等
- https://github.com/Viralmaniar/Remote-Desktop-Caching-    --Py。RDP信息复原，png图片格式。
- https://github.com/decalage2/oletools    --Py。用于分析MS OLE2文件（结构化存储，复合文件二进制格式）和MS Office文档。
- https://github.com/restic/restic    --数据备份、数据恢复
### Windows内存取证
- https://github.com/google/rekall    --Py。提取和分析数字Windows计算机系统
- https://github.com/volatilityfoundation/volatility    --Py。计算机内存取证
- https://github.com/gleeda/memtriage    --Windows内存取证分析
- https://www.xplico.org/download    --内存取证
- https://my.comae.com/tools    --DumpIt一款免安装的Windows内存镜像取证工具，可以使用其轻松的将一个系统的完整内存镜像下来
- https://github.com/volatilityfoundation/volatility    --windows内存取证分析
- https://github.com/comaeio/LiveCloudKd    --C。针对Hyper-V的内存取证。
## macOS取证
- https://github.com/CrowdStrike/automactc    --Py3。macOS环境自动化取证分类采集器。
## Linux取证
- https://github.com/snovvcrash/usbrip    --Py。Linux下带有CLI接口的开源取证工具，可用于跟踪/监控Linux机器上的USB设备连接事件（即USB事件历史记录，“已连接”和“已断开连接”事件）。
- https://github.com/sevagas/swap_digger    --针对 Linux swap 进行取证分析的工具
- http://extundelete.sourceforge.net/    --linux下的文件恢复
## 移动设备取证
- https://github.com/viaforensics/android-forensics    --安卓取证App和框架，可以对安卓设备内各种信息进行提取
- https://www.freebuf.com/articles/rookie/195107.html    --记一次微信数据库解密过程。微信的加密数据库的解密密码是由“设备的IMEI(MEID)+用户的uin，进行MD5，然后取其前7位小写字母”构成的
- 红队攻防之PC端微信个人信息与聊天记录取证 - https://mp.weixin.qq.com/s/4DbXOS5jDjJzM2PN0Mp2JA
- https://www.freebuf.com/news/193684.html    --iOS取证技巧：在无损的情况下完整导出SQLite数据库
- https://github.com/jfarley248/MEAT    --Py3。基于越狱与Cydia框架的IOS取证

## 网络取证
- wiki_TowerDefence.md    --网络威胁防御 流量协议分析
- https://github.com/Srinivas11789/PcapXray    --py。网络取证工具，可以捕获网络数据包，并可视化为包括设备标识的网络图，并突出显示重要的通信和文件操作。
- https://github.com/davidmcgrew/joy    --用来捕获和分析内外网流量数据的包，主要用于进行网络调查、安全监控和取证
- https://github.com/USArmyResearchLab/Dshell    --可扩展的网络取证分析框架，支持快速开发插件与解析网络数据包捕获
- http://f00l.de/pcapfix/    --pcap文件修复
### 数据隐秘传输
- wiki_ExpandAuth.md    --多姿态远程协助
- wiki_TowerDefence.md    --隐蔽隧道检测
- https://github.com/Arno0x/WSC2    --Py。利用web套接字WebSockets进行数据隐蔽传输
- https://github.com/Arno0x/DNSExfiltrator    --通过DoH利用dns加密请求进行数据泄露传输。
- https://github.com/Arno0x/ReflectiveDnsExfiltrator    --反射DNS解析隐蔽通道进行数据隐蔽通道
- https://github.com/no0be/DNSlivery    --Py3。基于scapy利用dns协议传输文件，条件简单。
- https://github.com/TryCatchHCF/Cloakify    --躲避DLP/MLS数据泄露防护系统，突破数据白名单控制，躲避AV检测进行数据盗取。
- https://github.com/sensepost/DET    --使用单个或多个通道同时执行数据取回。
- https://github.com/ytisf/PyExfil    --用于数据取回的Python软件包。
- https://github.com/christophetd/IPv6teal    --Py。利用ipv6隐蔽隧道传输数据。
### 邮箱取证
- https://github.com/RedLectroid/SearchOutlook/    --Outlook运行实例中关键字搜索
- https://github.com/dafthack/MailSniper    --PS。用于在Microsoft Exchange环境搜索电子邮件查找特定邮件（密码、网络架构信息等），提供分别针对OWA接口(Outlook Web App)、EWS接口和ActiveSync接口的password spray（多用户轮番爆破防检测）。
- https://github.com/euphrat1ca/OtherScript/blob/master/coremail_vul_check.sh    --coremail配置文件泄露导致用户导出/资产泄露/邮件伪造发送
- https://github.com/dpu/coremail-address-book/    /go。Coremail邮件系统组织通讯录导出脚本。
### 数据库取证
- https://github.com/vrana/adminer/    --php。php单文件数据库下载。phpstudy。
- https://github.com/abrignoni/DFIR-SQL-Query-Repo    --收集用于数据取证的SQL查询模板