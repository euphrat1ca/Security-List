# 欺骗防御
- https://github.com/paralax/awesome-honeypots/blob/master/README_CN.md    --开源蜜罐收集。goodjob。G:/OWASP/Honeypot-Project;P:/SDN网络微隔离;--
- https://www.freebuf.com/articles/paper/207739.html    --intro。开源蜜罐测评报告
- https://github.com/Cymmetria    --欺骗防御公司。Struts2、weblogic、telnet、Cisco ASA、Micros等仿真蜜罐，honeycomb低交互蜜罐框架
- https://www.freebuf.com/sectool/204652.html    --基于EVE-NG平台上构建企业内网攻防环境。
- https://github.com/BinaryDefense/artillery    --Py。端点蜜罐防护。
## 蜜罐服务
- https://github.com/phage-nz/malware-hunting    --Py。利用蜜罐进行恶意文件捕获。包含众多蜜罐使用说明。
- https://github.com/threatstream/mhn    --Py。现代蜜网，集成了多种蜜罐的安装脚本，可以快速部署、使用，也能够快速的从节点收集数据
- https://github.com/dtag-dev-sec/tpotce    --T-POT。里面使用docker技术实现多个蜜罐组合，配合ELK进行研究与数据捕获
- https://github.com/n3uz/t-pot-autoinstall    --Bash。将fork的T-POT蜜罐的一键安装脚本替换为国内加速镜像
- https://www.freebuf.com/sectool/190840.html    --Intro。T-Pot多蜜罐平台使用心法
- https://github.com/honeytrap/honeytrap    --Go。可扩展高交互蜜罐框架，侦听所有端口，监管蜜罐运行状态。
- https://github.com/honeynet/beeswarm    --Py。使用agent探针与蜜罐进行实时交互来引诱攻击者
### Web服务蜜罐
- https://github.com/p1r06u3/opencanary_web    --Py。基于TORNADO的低交互蜜罐。支持自动化安装，目前支持常见的16种协议，采用探针/蜜罐-管理的架构。可以考虑二次开发为探针-沙盒-管理的架构。
- https://github.com/seccome/Ehoney    --Go。基于云原生的欺骗防御系统，蜜标/蜜签/蜜罐诱饵
- https://github.com/hacklcx/HFish    --Go。多协议低交护蜜罐。goodjob。
- https://gitlab.com/SecurityBender/webhoneypot-framework    --Py3。基于docker和docker-compose，现支持wordpress/drupal
- https://github.com/mushorg/snare    --Py3。web安全蜜罐，可克隆指定Web页面。
- https://github.com/netxfly/x-proxy    --Go。代理蜜罐的开发与应用实战。simple
### PC服务蜜罐
- https://github.com/micheloosterhof/cowrie    --Py3。使用ELK（ElasticSearch，LogStash，Kibana）进行数据分析，目前支持ssh，telnet，sftp等协议蜜罐。
- https://github.com/desaster/kippo    --Py。蜜罐系统HoneyDrive下的图形化SSH蜜罐。1k。
- https://github.com/thinkst/opencanary    --Py3。SNMP\RDP\SAMBA蜜罐
- https://github.com/gosecure/pyrdp    --Py3。RDP MITM蜜罐
- https://gosecure.net/2018/12/19/rdp-man-in-the-middle-smile-youre-on-camera/    --Intro。基于PYRDP,打造可记录图像和按键的RDP蜜罐
- https://github.com/leeberg/BlueHive    --PS。利用Active Directory生成用户账户蜜罐
### 数据库蜜罐
- https://gitlab.com/bontchev/elasticpot    --py。Elasticsearch数据库蜜罐。
- https://github.com/codeplutos/MySQL-JDBC-Deserialization-Payload    --MySQL JDBC Deserialization Payload / MySQL客户端jdbc反序列化漏洞
### 供应链蜜罐。
- http://www.imooc.com/article/26398    --NodeJS应用仓库钓鱼。同理可应用于python库\apache module 后门等，相关诱饵名称可设置为加解密模块等，或者直接dns劫持。
### 物联网蜜罐
- https://github.com/alexbredo/honeypot-camera    --Py。摄像头蜜罐。tornado模拟WEB服务，图片代替视频，可以考虑后期多加点图片和按钮。
- https://github.com/EasyDarwin/EasyIPCamera    --C。RTSP服务器组件用以构建摄像头蜜罐。
- https://github.com/aau-network-security/riotpot    --IOT蜜罐协议

# 虚拟化
- http://www.linux-kvm.org    --Linux内核虚拟化工具，支持unix/win等多种系统。
- https://www.qemu.org    --纯软件实现的虚拟化环境仿真，硬件设备的环境模拟仿真。qemu-kvm为虚拟机管理工具
- https://www.busybox.net/    --集成了三百多个最常用Linux命令和工具的软件，良好支持嵌入式。
- https://www.virtualbox.org    --跨平台多系统支持，社区版。
- https://www.vmware.com    --跨平台多系统支持。ESXI虚拟化平台管理工具，vsphere集群。商业版。
- https://www.proxmox.com/    --Proxmox VE自带防火墙、邮件网关开源虚拟化平台，PVE类virtualbox架构。
- http://www.eve-ng.net    --UnifiedNetworking Lab统一网络实验室。基于Ubuntu深度定制。商业版。
- https://github.com/utmapp/UTM    --ios虚拟机
## 虚拟化云平台
- https://github.com/zstackio/zstack    --Java。类似openstack基于kvm与vmware的虚拟化云管理框架。商业版。
## 虚拟化容器
- https://github.com/moby/moby    --Go。Linux下虚拟容器dockerCE。54k。
- https://github.com/containers/podman    --管理 OCI 容器和 Pod，可基于已经调试好的镜像一键生成k8s部署yaml文件。
- https://github.com/containers/libpod    --Go。podman.io虚拟容器。3k。
- https://github.com/hashicorp/vagrant    --Ruby。自动化虚拟机管理工具。19k。
- https://www.cnblogs.com/ryanyangcs/p/12558727.html/    --两个奇技淫巧，将 Docker 镜像体积减小 99%。多阶段构建，系统精简。
### 虚拟化沙盒
- https://github.com/cuckoosandbox/cuckoo    --PY/JS。自动恶意软件分析系统，恶意样本分析沙盒检测。
- https://github.com/euphrat1ca/Panda-Sandbox    --Py。钟馗沙箱是基于cuckoo的适配国内软件环境的恶意软件检测
- https://github.com/sandboxie/sandboxie    --采用转换存储的隔离空间。Wilders社区，代码开源。goodjob。
- https://github.com/felicitychou/MalAnalyzer    --Py3。基于docker虚拟化的恶意代码沙箱。
- https://github.com/saferwall/saferwall    --Go。恶意软件沙盒协作平台，包含多家杀毒引擎。
- https://github.com/LloydLabs/wsb-detect    --Windows沙盒检测。