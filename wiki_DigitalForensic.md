# 数字取证
- http://xlysoft.net/    //SalvationDATA（效率源）取证工具。P:ios盘古;--
- https://github.com/alphaSeclab/awesome-forensics    //取证相关工具和文章。收集的所有开源工具: sec-tool-list;逆向资源: awesome-reverse-engineering;网络相关的安全资源: awesome-network-stuff;攻击性网络安全资源: awesome-cyber-security;开源远控和恶意远控分析报告: awesome-rat;Webshell工具和分析/使用文章: awesome-webshell;--
- https://github.com/laramies/metagoofil    //PY.从文件获取相关网站的用户名与邮箱等数据。documents (pdf,doc,xls,ppt,etc).
- https://github.com/mozilla/mig    //go.火狐mozilla基金会针对海量文件的内容定位工具，支持节点分级部署。Deprecation.
- https://polytechnic.purdue.edu/facilities/cybersecurity-forensics-lab/tools    //FileTSAR大规模的数据调查取证.
### 文件取证
- https://www.audacityteam.org/    //音频文件和波形图处理工具
- https://github.com/redaelli/imago-forensics    //PY2.将照片中Exif、MIME等信息提取存入CSV/sqlite中
- http://www.magicexif.com/    //将照片图像中的exif信息数据化
- http://mediaarea.net/MediaInfo    //类似于exiftool来查看内容区域和元数据信息
- https://www.sno.phy.queensu.ca/~phil/exiftool/    //检查图像文件的exif元数据
- https://www.gimp.org/    //Gimp提供了转换各类图像文件可视化数据的功能，还可以用于确认文件是否是一个图像文件
- http://qpdf.sourceforge.net/    //查看pdf文件并整理提取信息
- http://zipinfo.com/    //在无需提取的情况下列出了zip文件的内容信息
- https://github.com/GuidoBartoli/sherloq    //C++.数字图片取证
### 计算机设备取证
- https://www.ontrack.com/products/data-recovery-software/    //easyrecovery文件恢复软件。商业版。易我数据恢复;RECUVA
- http://www.diskgenius.cn/    //数据恢复/分区管理/备份还原。商业版。
- https://clonezilla.org/downloads.php    //再生龙(Clonezilla)是一个免费的灾难恢复、硬盘克隆、硬盘映像档制作的部署和解决方案,由台湾的国家高速网络与计算中心(国网中心)所开发
- https://www.cgsecurity.org/wiki/TestDisk    //磁盘分区修复
- https://github.com/decalage2/oletools    //PY.用于分析MS OLE2文件（结构化存储，复合文件二进制格式）和MS Office文档
- https://github.com/google/bochspwn-reloaded    //Bochspwn Reloaded（内核信息泄漏检测）工具
- https://github.com/comaeio/LiveCloudKd    //C.针对Hyper-V的内存取证
- https://github.com/sevagas/swap_digger    //针对 Linux swap 进行取证分析的工具
- http://extundelete.sourceforge.net/    //linux下的文件恢复
- https://github.com/SekoiaLab/Fastir_Collector    //Windows取证/信息收集，不限于内存，注册表，文件信息等
- https://github.com/Viralmaniar/Remote-Desktop-Caching-    //PY.RDP信息复原，png图片格式
- https://github.com/snovvcrash/usbrip    //PY.Linux下带有CLI接口的开源取证工具，可用于跟踪/监控Linux机器上的USB设备连接事件（即USB事件历史记录，“已连接”和“已断开连接”事件）。
- https://www.nirsoft.net/utils/usb_log_view.html    //USBLogView一款USB设备监控软件，后台运行，可以记录插入或拔出系统的任何USB的详情信息
- https://github.com/CrowdStrike/automactc    //PY2.macOS环境自动化取证分类采集器
#### 设备内存取证
- https://github.com/google/rekall    //PY.提取和分析数字Windows计算机系统
- https://github.com/volatilityfoundation/volatility    //PY.计算机内存取证
- https://github.com/gleeda/memtriage    //Windows内存取证分析
- https://www.xplico.org/download    //内存取证
- https://my.comae.com/tools    //DumpIt一款免安装的Windows内存镜像取证工具，可以使用其轻松的将一个系统的完整内存镜像下来
- https://github.com/volatilityfoundation/volatility    //windows内存取证分析
### 移动设备取证
- https://github.com/viaforensics/android-forensics    //安卓取证App和框架，可以对安卓设备内各种信息进行提取
- https://www.freebuf.com/articles/rookie/195107.html    //记一次微信数据库解密过程。微信的加密数据库的解密密码是由“设备的IMEI(MEID)+用户的uin，进行MD5，然后取其前7位小写字母”构成的
- https://www.freebuf.com/news/193684.html    //iOS取证技巧：在无损的情况下完整导出SQLite数据库
## 网络取证
- https://github.com/Srinivas11789/PcapXray    //py.网络取证工具，可以捕获网络数据包，并可视化为包括设备标识的网络图，并突出显示重要的通信和文件操作。
- http://f00l.de/pcapfix/    //pcap文件修复
- https://github.com/USArmyResearchLab/Dshell    //可扩展的网络取证分析框架，支持快速开发插件与解析网络数据包捕获
- https://github.com/abrignoni/DFIR-SQL-Query-Repo    //收集用于数据取证的SQL查询模板
- https://github.com/davidmcgrew/joy    //用来捕获和分析内外网流量数据的包，主要用于进行网络调查、安全监控和取证
- https://www.netresec.com/?page=Networkminer    ////网络取证分析工具，通过嗅探或者分析PCAP文件可以侦测到操作系统，主机名和开放的网络端口主机，解析http 2与TLS加密。产品包括网络取证与监控caploader 流量捕获、polarproxy tls加密流量代理等
### 数据取回隐秘传输
- https://github.com/TryCatchHCF/Cloakify    //躲避DLP/MLS数据泄露防护系统，突破数据白名单控制，躲避AV检测进行数据盗取
- https://github.com/sensepost/DET    //使用单个或多个通道同时执行数据取回
- https://github.com/Arno0x/DNSExfiltrator    //利用DNS解析进行数据隐秘传输的工具
- https://github.com/Arno0x/ReflectiveDnsExfiltrator    //反射DNS解析隐蔽通道进行数据泄露
- https://github.com/ytisf/PyExfil    //用于数据取回的Python软件包
### 协议解析流量分析数据还原
- http://www.colasoft.com.cn/download.php    //科来科来网络分析系统/ping工具/mac地址扫描工具/数据包重放工具/数据包生成工具
- https://github.com/wireshark/wireshark    //LUA.议解析流量分析还原。可通过Windows变量名“SSLKEYLOGFILE”的变量导出目标网站证书，进行密钥导入到Wireshark流量解析。
- http://www.tcpdump.org    //网络数据包截获分析
- https://github.com/didi/sharingan    //GO.流量录制，流量重放。testjob。
- http://lcamtuf.coredump.cx/p0f3    //C.p0f升级版，被动的流量指纹识别TCP/http
- https://github.com/zeek/zeek    //C++.bro的升级版，主要用于对链路上所有深层次的可疑行为流量进行安全监控，为网络流量分析提供了一个综合平台，特别侧重于语义安全监控。
- https://github.com/brimsec/brim    //JS.结构化日志查询引擎zq；用于多平台用户界面的Electron和React；以及从数据包捕获文件生成网络分析数据的Zeek，结合ws进行流量审计。testjob。
- https://github.com/0x4D31/fatt    //PY.利用tshark对流量进行解析
- https://github.com/netxfly/xsec-traffic    //GO.轻量级的恶意流量分析程序，包括传感器sensor和服务端server 2个组件。
- http://tcpick.sourceforge.net    //TCP流嗅探和连接跟踪工具
- https://github.com/secdev/scapy    //PY.内置了交互式网络数据包处理、数据包生成器、网络扫描器网络发现和包嗅探工具，提供多种协议包生成及解析插件，能够灵活的的生成协议数据包，并进行修改、解析。
- https://gitee.com/qielige/openQPA    //协议分析软件QPA的开源代码，特点是进程抓包、特征自动分析
- https://github.com/zerbea/hcxdumptool    //从Wlan设备上捕获数据包
- https://github.com/NytroRST/NetRipper    //支持截获像putty，winscp，mssql，chrome，firefox，outlook，https中的明文密码
- https://github.com/shramos/polymorph    //支持几乎所有现有协议的实时网络数据包操作框架
- https://github.com/nospaceships/raw-socket-sniffer    //C.PS.无需驱动抓取Windows流量
- https://github.com/netsniff-ng/netsniff-ng    //C.a fast zero-copy analyzer,pcap捕获和重放工具