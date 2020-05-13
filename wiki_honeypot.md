## 欺骗防御
- https://github.com/paralax/awesome-honeypots    //优秀蜜罐，相关技术手段收集。goodjob。G:OWASP/Honeypot-Project;P:SDN网络微隔离;--
- https://www.freebuf.com/articles/paper/207739.html    //intro。开源蜜罐测评报告
- https://github.com/Cymmetria    //欺骗防御公司。Struts2、weblogic、telnet、Cisco ASA、Micros等仿真蜜罐，honeycomb低交互蜜罐框架
- https://www.freebuf.com/sectool/204652.html    //基于EVE-NG平台上构建企业内网攻防环境
- https://github.com/BinaryDefense/artillery    //PY.端点蜜罐防护。
### 主动反制面包屑
- https://www.cnblogs.com/k8gege/p/12390265.html    //看我如何模拟Cobalt Strike上线欺骗入侵者
- https://www.freebuf.com/articles/ics-articles/230402.html    //一种工控蜜罐识别与反识别技术研究与应用实践
- https://www.freebuf.com/articles/system/232669.html    //内网Kerberos用户蜜罐。主动防御
### 蜜罐安全
- https://github.com/phage-nz/malware-hunting    //PY.利用蜜罐进行恶意文件捕获。包含众多蜜罐使用说明
- https://github.com/threatstream/mhn    //PY.现代蜜网，集成了多种蜜罐的安装脚本，可以快速部署、使用，也能够快速的从节点收集数据
- https://github.com/dtag-dev-sec/tpotce    //T-POT.里面使用docker技术实现多个蜜罐组合，配合ELK进行研究与数据捕获
- https://github.com/n3uz/t-pot-autoinstall    //bash.将fork的T-POT蜜罐的一键安装脚本替换为国内加速镜像
- https://www.freebuf.com/sectool/190840.html    //INTRO.T-Pot多蜜罐平台使用心法
- https://github.com/honeytrap/honeytrap    //GO.可扩展高交互蜜罐框架，侦听所有端口，监管蜜罐运行状态。testjob。
- https://github.com/honeynet/beeswarm    //PY.使用agent探针与蜜罐进行实时交互来引诱攻击者
### Web服务蜜罐
- https://github.com/p1r06u3/opencanary_web    //PY.基于TORNADO的低交互蜜罐。支持自动化安装，目前支持常见的16种协议，采用探针/蜜罐-管理的架构。可以考虑二次开发为探针-沙盒-管理的架构
- https://gitlab.com/SecurityBender/webhoneypot-framework    //PY3.基于docker和docker-compose，现支持wordpress/drupal
- https://github.com/mushorg/snare    //PY3.web安全蜜罐，可克隆指定Web页面
- https://github.com/netxfly/x-proxy    //GO.代理蜜罐的开发与应用实战。simple
### PC服务蜜罐
- https://github.com/hacklcs/HFish    //GO.redis\MYSQL\SSH etc 低交护蜜罐。goodjob。
- https://github.com/micheloosterhof/cowrie    //PY2.使用ELK（ElasticSearch，LogStash，Kibana）进行数据分析，目前支持ssh，telnet，sftp等协议
- https://github.com/desaster/kippo    //PY.蜜罐系统HoneyDrive下的图形化SSH蜜罐。1k。
- https://github.com/thinkst/opencanary    //PY2.SNMP\RDP\SAMBA蜜罐
- https://github.com/gosecure/pyrdp    //PY3.RDP MITM蜜罐
- https://gosecure.net/2018/12/19/rdp-man-in-the-middle-smile-youre-on-camera/    //INTRO.基于PYRDP,打造可记录图像和按键的RDP蜜罐
- https://blog.csdn.net/ls1120704214/article/details/88174003    //GO.反击mysql蜜罐。利用MySQL LOCAL INFILE读取客户端文件漏洞分析并使用Golang编写简易蜜罐;从MySQL出发的反击之路;Github:MysqlT，支持大文件无损传输，支持用户验证，支持自定义的 Mysql 版本，随机的盐加密，加上用户验证，让攻击者毫无察觉;Github:Rogue-MySql-Server
- https://github.com/leeberg/BlueHive    //PS.利用Active Directory生成用户账户蜜罐
- http://www.imooc.com/article/26398    //NodeJS 应用仓库钓鱼。同理可应用于python库\apache module 后门等，相关诱饵名称可设置为加解密模块等，或者直接dns劫持。
### 摄像头蜜罐
- https://github.com/alexbredo/honeypot-camera    //PY.摄像头蜜罐。tornado模拟WEB服务，图片代替视频，可以考虑后期多加点图片和按钮
- https://github.com/EasyDarwin/EasyIPCamera    //C.RTSP服务器组件用以构建摄像头蜜罐
### 工控蜜罐
- https://github.com/sjhilt/GasPot    //模拟油电燃气工控系统
- https://github.com/djformby/GRFICS    //IoT工业仿真系统模拟框架，采用MODBUS协议对PLC虚拟机监视和控制
- https://github.com/RabitW/IoTSecurityNAT    //IoT测试系统，方便快速接入各种设备，进行安全测试
- https://github.com/mushorg/conpot    //针对ICS/SCADA的低交互工控蜜罐，模拟Modbus和S7comm
- https://github.com/trombastic/PyScada/    //PY2.基于Django的SCADA操作管理系统