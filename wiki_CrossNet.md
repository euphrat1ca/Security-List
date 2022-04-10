# 代理映射穿透
- https://www.freebuf.com/sectool/249572.html    --正确的上网方式：软路由入门指南。techteach。
- https://github.com/fatedier/frp    --Golang。用于内网穿透的高性能的反向代理应用，多协议支持，支持点对点穿透，范围端口映射。greatjob,25k。G:todzhang/lcx/;G:/uknowsec/frpModify --公众号:FRP改造计划;--
- https://github.com/cnlh/nps    --Go。内网穿透代理服务器。支持tcp、udp流量转发，支持内网http代理、内网socks5代理，同时支持snappy压缩、站点保护、加密传输、多路复用、header修改等。WebGUI,多用户。GOODJOB。G:/stealth/psc;--
- https://github.com/Dliv3/Venom    --Go。类似于Termite/EarthWorm架构的多节点流量代理、端口转发、端口复用。goodjob。W:rootkiter.com/Termite/;G:/ls0f/gortcp;Github:/rtcp;Github:/NATBypass;--
## 流量代理
- https://github.com/litespeedtech    --轻量级高并发web框架，自带waf/管理后台/模板等。类比nginx。W:openlitespeed.org;--
- http://openresty.org/    --基于Nginx+Lua的高性能 Web 平台
- https://github.com/goproxy/goproxy    --Golang代理模块。G:/snail007/goproxy;--
- https://github.com/sergeyfrolov/httpt    --响应TLS来降低代理被识别的几率。
### 流量转发
- https://github.com/inconshreveable/ngrok    --Go。端口转发，正反向代理，内网穿透。17K。
- https://github.com/L-codes/Neo-reGeorg    --Py。`reDuh reGeorg`的升级版，把内网端口通过http/https隧道转发形成回路。用于目标服务器在内网或做了端口策略的情况下连接目标服务器内部开放端口（提供了php，asp，jsp脚本的正反向代理）。goodjob。G:/sensepost/reGeorg;G:/SECFORCE/Tunna;G:/securesocketfunneling/ssf;G:/sysdream/ligolo;G:/FunnyWolf/pystinger;--
- https://github.com/hayasec/reGeorg-Weblogic    --适配老版本weblogic。
- https://github.com/fbkcs/thunderdns    --Py。将tcp流量通过DNS协议转发，不需要客户端和socket5支持。
- https://github.com/esrrhs/pingtunnel    --go。构建icmp隧道转发tcp/udp/sock5流量，端口转发、绕过验证，界面GUI。G:/jamesbarlow/icmptunnel;--
- https://github.com/blackarrowsec/mssqlproxy    --PY。利用sql server进行内网流量代理。
### 端口转发
- https://github.com/ph4ntonn/Stowaway    --Go。树状节点代理。welljob。
- https://github.com/vzex/dog-tunnel    --Go。Linux下基于kcp的p2p端口映射工具，同时支持socks5代理。2k。
- https://github.com/decoder-it/psportfwd    --PowerShell。无需admin权限进行端口转发。
- https://github.com/davrodpin/mole    --Go。基于ssh的端口转发。
### 端口复用
- https://github.com/YDHCUI/TcpTunnel    --Py。通过识别不同协议头路由转发到对应的端口服务。goodjob。Knockd敲门复用。
- https://nets.ec/Shellcode/Socket-reuse    --C。套接字重用。
- https://mp.weixin.qq.com/s/dSPL4YfvSN8Awo6bKbHPCA     --ShadowMove套接字劫持技术分析，巧妙隐藏与C2的连接
- https://github.com/earthquake/UniversalDVC    --C++。利用动态虚拟通道注册dll文件，进行rdp服务端口复用
- https://github.com/cloudflare/mmproxy    --C。在负载均衡HAProxy代理的基础上支持proxy-protocol协议，可以传递客户端TCP协议的真实IP。配合Netsh、Iptables实现端口复用。
- https://github.com/BeetleChunks/redsails    --PY,C++。利用WinDivert驱动程序与windows内核交互，不更改端口开放状态进行端口复用TCP流量到另一个主机，在目标主机上执行命令且无需创建任何事件日志以及网络连接，可使用powershell。testjob。
- https://github.com/Pandentia/protoplex    --Go。OpenVPN、SSH、SOCKS、http/s协议多路复用器。
### 流量代理池
- https://www.ip12345.net/    --鲸鱼代理 动态IP修改
- https://github.com/Python3WebSpider/ProxyPool    --Py3。
- https://github.com/imWildCat/scylla    --Py3。智能代理池。G:/Python3WebSpider/ProxyPool;G:/SpiderClub/haipproxy;G:/chenjiandongx/async-proxy-pool;G:/TideSec/Proxy_Pool;--
- https://github.com/audibleblink/doxycannon    --Py。使用一个openvpn代理池，为每一个IP生成docker进行连接，当连接某一个vpn后，其它的进行socks5转发做流量分发。
- https://github.com/realgam3/pymultitor/    --Py。使用多线程Tor代理。
- https://github.com/hevnsnt/IPChanger    --Py。使用tor动态ip socks代理。

## Cross超越边界
- https://github.com/bannedbook/fanqiang/wiki    --cross汇总
- https://github.com/netchx/Netch    --C#。类似于sockscap64，支持进程选择代理，通过虚拟网卡转为类VPN全局代理，需要```.NetFramework4.8```。goodjob。
- https://www.proxifier.com/    --商业版流量进程代理。W:ccproxy;W:SSTAP;W:Proxifier v3.42中文版;--
- https://github.com/Dreamacro/clash    --基于规则的跨平台代理客户端。G:/BoyceLig/Clash_Chinese_Patch;G:/yichengchen/clashX;G:/Kr328/ClashForAndroid;--
### 多姿态代理服务
- https://github.com/jinwyp/one_click_script/blob/master/README_CN.md    --一键部署BBR/v2/trojan。G:/ToyoDAdoubi/doubi;G:/JeannieStudio/all_install;--
- https://github.com/gwuhaolin/lightsocks    --Go。轻量网络混淆代理。
- https://github.com/txthinking/brook    --Go。跨平台强加密无特征的代理软件，多客户端。G:/Ccapton/brook-ok;G:/Ccapton/brook-web;--
- https://github.com/Umbrellazc/BypassCampusNet    --校园网防断网，UDP 53 免流上网。
- https://ding-doc.dingtalk.com/doc#/kn6zg7/hb7000    --钉钉内网穿透。G:/open-dingtalk/pierced;--
### Shadowsocks代理
- https://github.com/Anankke/SSPanel-Uim    --PHP。基于 ss-panel-v3-mod多用户管理面板
- https://github.com/ssrpanel/SSRPanel    --ss ssr v2ray用户分布式管理。G:/xuanhuan/ss-panel;G:/shadowsocks/shadowsocks-manager;G:/Ehco1996/django-sspanel;G:/leitbogioro/SSR.Go;--
- https://doubibackup.com/    --一个逗比写的各种逗比脚本。/ToyoDAdoubiBackup/doubi/;G:/shadowsocks/go-shadowsocks2;--
- https://github.com/shadowsocksrr/shadowsocksr    --酸酸乳。G:/WooSoftware/shadowsocksr-origin;--
- https://github.com/guyingbo/shadowproxy    --ss socks5 http https 等多种网络代理。
- https://github.com/ginuerzh/gost    //基于shadowsocks-go库的socket代理
### V2ray&Trojan
- https://github.com/v2fly/fhs-install-v2ray    ---Go。Vemss\Vless网络框架服务端安装。G:/233boy/v2ray/wiki/V2Ray一键安装脚本;G:/wulabing/V2Ray_ws-tls_bash_onekey/--
- https://github.com/AstralHope/v2-ui    --Py。多协议租户的 v2ray 面板。G:/Jrohy/multi-v2ray;G:/vaxilu/x-ui;--
- https://github.com/2dust/v2rayNG    --kotlin。V2ray安卓客户端。G:/2dust/v2rayN;--
- https://github.com/yanue/V2rayU    --Swift。基于v2ray核心的mac版客户端，多协议支持。G:/Cenmrev/V2RayX;--
- https://itunes.apple.com/us/app/kitsunebi-proxy-utility/    --美区V2ray IOS客户端，PP助手IPA文件。P:Shadowrocket;P:Pepi;P:i2Ray;P:Quantumult;--
- https://github.com/trojan-gfw    --C++。跨平台代理服务。G:/p4gefau1t/trojan-go --CDN加强版/自动证书申请/多路复用/路由功能;--
- https://iyideng.vip/black-technology/cgfw/trojan-go.html    --trojan一键部署。G:/Jrohy/trojan --webgui管理多用户管理部署程序;G:/V2RaySSR/Trojan/;--
### 游戏加速
- https://github.com/shadowsocks/v2ray-plugin    --基于Nginx流量混淆http。G:/shadowsocks/simple-obfs/;--
- https://github.com/cbeuw/Cloak    --流量加密审查规避。G:/HirbodBehnam/Shadowsocks-Cloak-Installer;--
- https://github.com/wangyu-/udp2raw/ --UDP协议伪装。G:/wangyu-/tinyfecVPN/;--
- https://ssr.tools/588    --ss+kcptun+udp2raw bypass qos。G:/233boy/udp2raw/;G:/kuoruan/shell-scripts/;--
- https://github.com/wangyu-/UDPspeeder    --C++。双边网络加速工具speederv2。
- https://github.com/xtaci/kcptun    --Go。基于KCP协议的UDP隧道。G:/skywind3000/kcp;G:/clangcn/kcp-server;--
- https://gitee.com/ragnaroks/KcptunGUI    --C#。kcptun配置工具。G:/dfdragon/kcptun_gclient/;G:/GangZhuo/kcptun-gui-windows/;--
- https://cmy2.network/register?aff=iydcc    --CMYNetwork红莓网络
- https://justmysocks.xyz/justmysocks-v2ray/    --搬瓦工加速器
- https://github.com/selierlin/Share-SSR-V2ray/blob/master/1-share-ssr-v2ray.md    --飞机加速器。W:psiphon3.com;W:mono.sh --mymonocloud;W:windscribe.com;W:hide.me;W:paofu.cloud/;--
- https://github.com/ntkernel/lantern    --蓝灯无限流量unlimited-landeng-for-win
- https://suying222.net/auth/register?code=9Hrs    --海外加速器

## Cross自组网
- https://github.com/proxycannon/proxycannon-ng    --Shell。从云端获取IP节点流量，构建Tor洋葱私人网络，形成僵尸网络组建。
- https://github.com/slackhq/nebula    --GO。slack采用p2p自组网。goodjob。P:/红蓝对抗之组一个安全的网;--
- https://github.com/zerotier    --C++。网络虚拟化平台云自组网。
- https://www.radmin-vpn.cn/    --远程组网服务。
- https://github.com/microsoft/SDN    --PS。此存储库包括脚本，模板和示例交换机配置，以帮助管理员部署Windows Server 2016软件定义网络（SDN）堆栈并将其连接到其现有网络拓扑。
- https://feisky.gitbooks.io/sdn/    --sdn-handbook SDN网络指南
### VPN虚拟网络
- https://github.com/teddysun/across    --秋水逸冰一键安装脚本。G:/Nyr/openvpn-install;--
- https://ocserv.gitlab.io    --VPN服务端 Cisco Anyconnect 替代品
- http://www.vpngate.net    --日本国立筑波大学开源云局域网SoftEther，L2TP GUI。
- https://help.aliyun.com/document_detail/65374.html    --strongswan IPsec VPN。G:/quericy/one-key-ikev2-vpn;--
- https://github.com/slackhq/nebula    --Go。跨平台P2P异地组网。P:tailscale;P:zerotier;--
- https://github.com/ntop/n2n    --Go。supernode虚拟网络VPN软件
#### WireGuard
- https://www.wireguard.com/install/    --基于UDP跨平台VPN协议，一键组网切换。G:/atrandys/wireguard;W:teddysun.com/554.html/;G:/angristan/wireguard-install/;
- https://naiv.fun/Ops/53.html    --安装 Wireguard 并组建中心辐射型网络。G:/WireGuard/wireguard-go;G:/P3TERX/script/blob/master/wireguard-go.sh;G:/P3TERX/wireguard-go-builder/releases/latest;--
- https://docs.netmaker.org/quick-start.html    --Go。基于 WireGuard mesh network 网状网络网络控制工具。G:/gravitl/netmaker/blob/master/scripts/nm-quick.sh;W:nip.io --泛域名解析;--
- https://github.com/subspacecommunity/subspace    --Wireguard Server GUI。G:/ViRb3/wgcf--
- https://tunsafe.com/download    --wg客户端。W:wireguardconfig.com/;--