# 逆向破解分析
- https://www.pelock.com/articles/reverse-engineering-tools-review    --Reverse engineering tools review 逆向工具测评
- https://down.52pojie.cn/    --吾爱破解爱盘工具包。W:tool.pediy.com/;--
- https://www.peerlyst.com/posts/resource-learning-how-to-reverse-malware-a-guide    --恶意软件逆向指南和工具的集合
- https://github.com/alphaSeclab/awesome-reverse-engineering    --Reverse Engineering Resources About All Platforms(Windows/Linux/macOS/Android/iOS/IoT)3000+逆向资源合集。
- https://www.chinapyg.com/forum.php?mod=viewthread&tid=83083    --Baymax Patch Tools（简称 Baymax）Parch补丁生成，。P:keymaker2;--
## 反调试检测
- https://github.com/LloydLabs/wsb-detect    --C。检测是否为Windows沙盒。
### 应用服务诊断
- https://github.com/alibaba/arthas    --阿里开源的Java诊断的工具。W:如何使用Arthas进行JVM取证;--
- https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/getting-started-with-windbg    --Windows应用诊断调试。
- https://www.freebuf.com/articles/network/103816.html    --使用Windbg和Python进行堆跟踪。PyKd
### 程序调试管理
- https://www.cheatengine.org    --CE（Cheat Engine）是一款内存修改编辑工具，程序函数监控，配合Ultimap功能食用游戏魔改更佳。
- http://www.angusj.com/resourcehacker    --Windows二进制文件浏览编辑 (*.exe; *.dll; *.scr; etc) 和资源文件修改 (*.res, *.mui)图标属性等。Resource Hacker类似于于Restorator文件资源修改软件。
- https://github.com/euphrat1ca/PeDoll    --C++。基于inlineHook技术的软件分析工具，C/S架构（PeDollc/PeDolls）。
- https://bbs.ichunqiu.com/thread-16846-1-1.html    --intro。PeDoll 调戏木马病毒的正确姿势-正式篇
- https://github.com/everdox/InfinityHook    --C++。挂钩系统调用，上下文切换，页面错误等。
- https://github.com/fireeye/capa    --Py。Windows下程序执行时所产生的操作。goodjob。
### 防护软件列表
- https://github.com/gh0stkey/avList    --杀软列表。G:/r00tSe7en/get_AV;--
- https://github.com/3had0w/Antivirus-detection    --cobaltstrike插件。检测杀软进程对应杀软名称标注。G:/ars3n11/Aggressor-Scripts;--
- https://github.com/uknowsec/SharpAVKB    --Windows杀软进程、补丁号列表。G:/Ch1ngg/GetWindowsKernelExploitsKB;--
- https://github.com/PwnDexter/SharpEDRChecker    --杀毒软件AV、终端防护EDR、日志记录工具等防护软件列表。G:/PwnDexter/Invoke-EDRChecker;--

## 小程序安全
- https://developers.weixin.qq.com/miniprogram/dev/devtools/download.html    /微信小程序开发工具
- https://github.com/xuedingmiaojun/mp-unpack    --electron-vue。微信小程序自助解包客户端。
- https://github.com/sjatsh/unwxapkg    --Go。微信小程序反编译。G:/oujunke/UnWechatApp;G:/xuedingmiaojun/wxappUnpacker;G:/leo9960/wechat-app-unpack;--
- https://github.com/Cherrison/CrackMinApp    --C#,Node.js。(反编译微信小程序)一键获取微信小程序源码(傻瓜式操作)。goodjob。

## 客户端安全
- http://www.rohitab.com/apimonitor    --客户端C/S架构API接口监控工具
- https://github.com/theLSA/hack-cs-tools    --客户端测试工具检查条目checklist。G:/theLSA/CS-checklist;--
### RTOS逆向分析
- https://github.com/PAGalaxyLab/vxhunter    --Py。一个用于VxWorks嵌入式设备分析的工具集，包含固件分析，串口调试，通过IDA Pro 7.x 、Ghidra 9.x 、Radare2 插件脚本对VxWorks设备调试。
- https://www.rubydoc.info/github/rapid7/metasploit-framework/Msf/Exploit/Remote/WDBRPC    --wdbrpc内存dump
### PC端逆向分析
- https://www.hex-rays.com    --IDA pro反汇编工具。商业版。W:youtu.be/qCQRKLaz2nQ;--
- https://github.com/xrkk/awesome-ida    --IDA Pro有关的资源收集
- https://github.com/onethawt/idaplugins-list    --IDA Plugins插件集合
- https://github.com/NationalSecurityAgency/ghidra    --Java。NSA出品的软件逆向动态调试框架Ghidra。类IDA架构。
- https://github.com/ghidraninja/ghidra_scripts    --Py。Ghidra的Binwalk、Yara联动插件。
- https://hackaday.io/project/172292-introduction-to-reverse-engineering-with-ghidra    --Intro。Ghidra教程。
- https://www.kanxue.com/book-brief-64.htm    --Ghidra操作手册。商业版。
- https://github.com/radare/radare2    --C。radare2是基于Capstone的跨平台逆向工程平台。包括反汇编、分析数据、打补丁、比较数据、搜索、替换、虚拟化等。10k。goodjob。
- https://github.com/radareorg/cutter    --C++。基于QT的radare2框架GUI。goodjob。
- https://github.com/armijnhemel/binaryanalysis-ng    --Py3。Binary Analysis Toolkit（BAT），对固件、二进制、pwn等文件进行递归式解压缩实现识别与逆向。goodjob。
- https://github.com/angr/angr    --Py。二进制分析工具,支持动态符号执行和静态分析。3k。
- https://github.com/x64dbg/x64dbg    --C++。Windows调试工具x64dbg/x32dbg。greatjob。34k。W:immunityinc.com --Immunity Debugger;P:/32位汇编分析调试器Ollydbg;G:/horsicq/x64dbg-Plugin-Manager;--
- https://github.com/ReFirmLabs/binwalk    --Py。固件、二进制、pwn等文件自动化识别与逆向，支持多插件配置。goodjob,5k。
### 查脱壳操作
- https://github.com/slimm609/checksec.sh    --bash。用于检查可执行文件的属性。goodjob。
- https://mp.weixin.qq.com/s/-ljFc5sBn9Sq92Pboy0SWQ    --傻瓜式脱壳保姆级教学
- http://www.legendsec.org/1888.html    --pkid查壳工具，APK查壳工具PKID ApkScan-PKID。P:DetectItEasy;--
- https://github.com/rednaga/APKiD    --Py。查找Android应用程序Yara标识符的封隔器，保护器，混淆器 - PEiD for Android。goodjob。
- https://github.com/DrizzleRisk/drizzleDumper    --Android脱壳工具。G:/TUnpacker;G:/BUnpacker;G:/halfkiss/ZjDroid;--
- https://www.jianshu.com/p/6a504c7928da    --Android常见App加固厂商脱壳方法的整理
- https://github.com/hluwa/FRIDA-DEXDump    --py。暴力搜索 dex035，脱壳dump内存中的dex。
### PE分析操作
- https://github.com/horsicq/Detect-It-Easy    --C。官网```ntinfo.biz```，PE侦壳工具可以查看EXE/DLL文件编译器信息、是否加壳、入口点地址、输出表/输入表等信息。W:exeinfo.xn.pl;--
- https://ntcore.com/?page_id=388    --PE32 & PE64编辑工具，支持.NET文件格式。
### 汇编反编译
- https://github.com/blackberry/pe_tree    --Py,QT。PE逆向，树形结构图查看PE结构、复制内存中的PE文件并执行导入重构，可作为IDAPython插件加载。
- https://github.com/endgameinc/xori    --RUST。自定义反汇编框架，PE32, 32+ and shellcode。
- https://github.com/blacknbunny/peanalyzer32    --Py3。PE 文件分析和反汇编工具
- https://github.com/aquynh/capstone    --C。Capstone是一个轻量级的多平台多架构支持的反汇编框架。支持包括ARM，ARM64，MIPS和x86/x64平台。4k。
- https://github.com/joxeankoret/pyew    --Py。基于Capstone的深度代码分析和文件修改工具。支持PE、ELF、OLE2、PDF等格式，并且支持自定义插件
### VB/易语言/C#逆向
- https://github.com/icsharpcode/ILSpy    --C#。针对exe反编译软件。8k。goodjob。
- https://github.com/0xd4d/dnSpy    --C#。dnSpy is a debugger and .NET assembly editor，支持断点调试、Unity调试。goodjob。
- https://www.vb-decompiler.org/products/cn.htm    --VB Decompiler是针对Visual Basic 5.0/6.0开发的程序反编译器
- https://github.com/0xd4d/de4dot/    --C#。反混淆.Net代码逆向解压。
- https://www.jetbrains.com/decompiler/    C#反编译，NiceDotPeek可显示代码注释。
### Python逆向
- https://sourceforge.net/projects/pyinstallerextractor    --Py。pyinstaller'*.exe'反编译为'.pyc'
- https://github.com/countercept/python-exe-unpacker    --Py。Linux下py2exe or pyinstaller打包文件解压缩、逆向代码。
- http://tools.bugscaner.com/decompyle    --'.pyc .pyo'文件在线反编译
- https://github.com/rocky/python-uncompyle6    --Py3。支持Python version 1.3 to version 3.7源码反编译'*.pyc'。
- https://github.com/wibiti/uncompyle2    --Py3。针对python2.7源码反编译
- https://sourceforge.net/projects/easypythondecompiler    --Easy Python Decompiler利用 "Uncompyle2" & "Decompyle++"，支持'.pyc 1.0 - 3.4'源码反编译，界面GUI。
- https://github.com/zrax/pycdc    --C++。Linux全版本*.pyc反编译。
### Java逆向
- https://github.com/skylot/jadx    --Java。jd-gui反编译工具升级版，反编译出来的代码未格式化。20k。G:/java-decompiler/jd-gui;--
- https://github.com/deathmarine/Luyten    --Java。java反编译、代码格式化，解决jd的INTERNAL ERROR问题。3k。
- https://github.com/pxb1988/dex2jar    --Java。android/.dex/.class文件逆向反编译为java代码，dex-tools SNAPSHOT。
- https://github.com/Col-E/Recaf    --java。java字节码编辑器。
### 安卓逆向
- https://www.jianshu.com/p/a12d04fc748f    --Android逆向分析大全
- https://securityoversimplicity.wordpress.com/2017/04/29/android-reversing-part-2-tools/    --安卓逆向工具
- https://www.andreafortuna.org/2019/07/18/reverse-engineering-and-penetration-testing-on-android-apps-my-own-list-of-tools/    --安卓应用分析工具
- https://www.pd521.com    --逆向未来，android逆向菜鸟速参手册完蛋版，AndroidKiller安卓逆向工具。P:/apk改之理ApkIDE;--
- https://github.com/Surendrajat/APKLab    --vs code APK分析插件
- http://www.gda.wiki:9090/    --Java。全交互式的现代反编译器。G:charles2gan/GDA-android-reversing-Tool;--
- https://github.com/iBotPeaches/Apktool    --java。Android逆向apk反编译工具.8K.
- https://github.com/UltimateHackers/Diggy    --Bash。基于apktool反编译后正则匹配从 Apk 文件中提取 URLs 的工具，apkurl。simple
- https://github.com/TheKingOfDuck/ApkAnalyser    --py。安卓应用敏感信息提取。用户密码、aksk
### Javascript逆向
- https://www.zyxiao.com/p/39429/    --记录一次前端JS加密绕过 ｜ 绕过前端解密的两种方法
### OSX/IOS逆向
- https://github.com/0x36/ghidra_kernelcache    --iOS内核逆向框架
- https://github.com/ptswarm/reFlutter    --Flutter逆向分析工具
### PHP逆向分析
- https://www.jb51.net/softs/558419.html    --SeayDzend，支持zend5.2/zend5.3/zend5.4 PHP解密