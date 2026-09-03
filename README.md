<p align="center">
  <img src="docs/assets/autocar-logo.svg" width="720" alt="AutoCAR — secure dual-ended accelerator">
</p>

<h1 align="center">AutoCAR</h1>

<p align="center">安全、可测量、拥有独立协议实现的 Go 双端网络加速器</p>

<p align="center">
  <a href="https://github.com/cppla/autocar/actions/workflows/ci.yml"><img src="https://github.com/cppla/autocar/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/cppla/autocar/actions/workflows/codeql.yml"><img src="https://github.com/cppla/autocar/actions/workflows/codeql.yml/badge.svg" alt="CodeQL"></a>
  <a href="https://github.com/cppla/autocar/actions/workflows/netem.yml"><img src="https://github.com/cppla/autocar/actions/workflows/netem.yml/badge.svg" alt="netem integration"></a>
  <a href="https://github.com/cppla/autocar/actions/workflows/fuzz.yml"><img src="https://github.com/cppla/autocar/actions/workflows/fuzz.yml/badge.svg" alt="scheduled fuzzing"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-22c55e.svg" alt="MIT License"></a>
</p>

AutoCAR 在本地提供 SOCKS5、HTTP 和 HTTPS Proxy，在远端解析并连接目标。TCP 流复用一条长期 QUIC 连接，SOCKS5 UDP 通过有界 QUIC DATAGRAM 会话传输；UDP 不可达时，`auto` 模式会把新 TCP 流切换到独立的 TLS 1.3/TCP 通道。

AutoCAR 采用独立协议与实现。Hysteria v2 仅作为公开设计参考；项目不包含
其源码，也不兼容其 wire protocol。项目使用上游 `quic-go`，身份验证、
`autocar/2` 协议、TCP/UDP framing、速率协商、pacing、熔断回退和资源边界
均由 AutoCAR 实现。

## 借鉴什么，实际实现什么

| 公开设计目标 | AutoCAR 的独立实现 | 不作出的承诺 |
| --- | --- | --- |
| Hysteria v2 的长连接、多流和 DATAGRAM 思路 | TLS 1.3 QUIC 热连接；每个 TCP 流独立；自有 `ACDG` UDP 分片/重组；真实 TCP/TLS fallback | 不提供 Hysteria 兼容模式、HTTP/3 cover、Salamander、Chrome 指纹或 Fast Open |
| BBR 的带宽/RTT 模型思想 | `adaptive` 在应用发送层观察 quic-go 的累计发送、丢失、min RTT 和 smoothed RTT，以有界的近似 delivery-rate 窗口和 pacing gain 调节写入 | 不是 Linux BBR，也不替换 quic-go 的拥塞窗口、ACK、重传或底层 Reno 控制器 |
| ServerSpeeder/LotServer 的公开体验目标 | 双端独立 sender pacing、热连接状态复用、有界流式回压、QUIC 标准丢失恢复 | 不复制任何专有预测算法，不做内核透明代理、FEC、抢先重传或包复制 |
| 已知容量链路的固定发送 | 双方通过 AutoCAR v2 协商显式上限，使用有界 token bucket | 不称为 Brutal；不是不可绕过的流量 policer，也不保证对其他流公平 |

默认 `adaptive-balanced` 是一个 **BBR-inspired 应用层 pacer**。底层 QUIC 仍由上游 quic-go 的拥塞控制和 RFC 9002 recovery 保证安全性；`reno` 模式只是关闭 AutoCAR 应用层 pacing，用作底层基线。完整边界见 [加速设计](docs/ACCELERATION.md)。

## 安全与代理能力

- SOCKS5 CONNECT 与 UDP ASSOCIATE、HTTP absolute-form/CONNECT、可选本地 HTTPS Proxy。
- TLS 1.3、正常的 X.509 SAN/链验证、强制共享令牌、可选 mTLS；没有跳过证书验证的开关。
- 服务端先解析域名，再对数字 IP、端口、特殊用途地址、私网和自定义 CIDR 执行出口策略，避免二次 DNS rebinding。
- QUIC 连接、并发流、待打开请求、UDP 会话、分片重组字节、HTTP 头和出口 socket 都有上限。
- `auto` 模式用冷却熔断器限制新 TCP 流因 UDP 黑洞反复等待；fallback 只承载
  TCP。SOCKS5 UDP 在 `auto` 中仍只尝试 QUIC，QUIC 不可用时 association 会失败。
- 客户端在实际成功完成 QUIC→TLS 切换或 QUIC 路径恢复时记录固定枚举的
  `event`/`reason`；该事件路径不包含令牌、完整目标、relay 地址或原始错误文本。
  回调按状态提交顺序异步串行分发，待处理队列有界并在拥塞时合并中间事件；此时
  并发安全的 `Snapshot` 是最终状态依据。最近完成的路径与 QUIC 熔断健康状态彼此独立。

中继知道目标地址，也可能看到目标侧明文；应用仍应使用 HTTPS、SSH 等端到端协议。AutoCAR 不承诺流量不可识别，也不承诺任何路径一定比直连更快。

## 快速开始

需要 Go 1.25.13 或更高版本：

```bash
git clone https://github.com/cppla/autocar.git
cd autocar
go build -trimpath -o autocar ./cmd/autocar
```

生成独立令牌与含真实 SAN 的证书：

```bash
./autocar token --out token
./autocar cert --hosts relay.example.com,203.0.113.10 --cert server.crt --key server.key
```

服务端的 UDP 与 TCP 可以使用相同端口号；这里先使用非特权端口：

```bash
./autocar server \
  --listen :8443 \
  --tcp-listen :8443 \
  --cert server.crt \
  --key server.key \
  --token-file token
```

客户端：

```bash
./autocar client \
  --server relay.example.com:8443 \
  --ca server.crt \
  --token-file token
```

在启动本地代理前，可用同一组隧道参数做一次真实端到端探测：

```bash
./autocar doctor \
  --server relay.example.com:8443 \
  --ca server.crt \
  --token-file token \
  --transport auto \
  --target example.com:443
```

`doctor` 不以“本地端口已监听”代替中继健康。它会通过经过证书和令牌认证的
隧道实际打开一次目标 TCP 连接，再报告真正选中的 `quic` 或 `tls`、客户端与
中继端 pacing、协商后的双向固定速率和耗时。加 `--json` 可得到稳定的机器可读
结果；失败 JSON 只包含稳定错误码和脱敏说明，原始网络错误、远端消息及本地路径仅在
人类输出的诊断日志中出现。退出码 `0` 表示探测成功，`1` 表示网络/认证/目标探测
失败，`2` 表示参数或本地配置错误。成功只证明该 TCP 路径此刻可用，不代表目标应用
协议正确或链路更快。

生产环境若直接绑定 `443`，应给服务进程最小的 `CAP_NET_BIND_SERVICE` 能力，
或在主机/容器外层做端口映射；不要仅为绑定低端口而以 root 运行整个中继。

默认入口：

| 入口 | 地址 | 示例 |
| --- | --- | --- |
| SOCKS5 TCP/UDP | `127.0.0.1:1080` | `curl --proxy socks5h://127.0.0.1:1080 https://example.com` |
| HTTP Proxy | `127.0.0.1:8080` | `curl --proxy http://127.0.0.1:8080 https://example.com` |
| HTTPS Proxy | 默认关闭 | 使用 `--https`、`--proxy-cert`、`--proxy-key` 开启 |

`socks5h` 会把域名交给远端。AutoCAR 不伪造目标证书，也不解密目标 HTTPS。

## Pacing 模式

```bash
# 默认：温和探测带宽并根据 RTT/loss 收敛
./autocar client [连接参数] --pacing adaptive --pacing-profile balanced

# 共享链路更保守
./autocar client [连接参数] --pacing adaptive --pacing-profile conservative

# 不使用 AutoCAR 应用层 pacing；观察当前 quic-go/Reno 基线
./autocar client [连接参数] --pacing reno
```

只有测得真实容量时才使用 `fixed-rate`。该模式只在 QUIC 路径上协商；上传和下载
按方向协商，服务端上限优先：

```bash
./autocar server [服务端参数] \
  --pacing fixed-rate \
  --max-upload-mbps 80 \
  --max-download-mbps 250 \
  --allow-client-rates

./autocar client [连接参数] \
  --transport quic \
  --pacing fixed-rate \
  --upload-mbps 60 \
  --download-mbps 200
```

错误的固定速率会制造队列和丢包。`--transport=auto` 的 TCP/TLS fallback 不保留
QUIC pacing；需要严格的 fixed-rate 语义时应显式使用 `--transport=quic`。协议 pacing
不能约束恶意客户端；硬限速必须使用主机或云网络 policer。

## 本地入口与出口策略

无认证入口只能绑定环回。SOCKS5 用户名密码和 HTTP Basic 在本地这一跳是明文；跨主机应开启 HTTPS Proxy。客户端信任方式必须二选一：`--ca <PEM>` 或显式 `--system-roots`。mTLS 使用服务端 `--client-ca` 与客户端 `--client-cert/--client-key`。

默认拒绝环回、链路本地、多播、未指定和 IANA 特殊用途地址，以及端口 `25,465,587`。`--allow-private` 仅允许 RFC1918、ULA 和 CGNAT；`--deny-cidrs`、`--deny-ports` 可进一步收紧。

## 兼容性

当前协议 ALPN 是 `autocar/2`。它与 Hysteria v2、旧 AutoCAR v1 都不兼容；升级必须同时更新两端或临时使用不同端口进行迁移。`client --transport` 仅接受 `auto`、`quic`、`tls`；`bench-client` 另提供 `direct` 对照路径。

## 验证

```bash
go test ./...
go test -race ./...
go vet ./...

make integration-docker
make build
sudo ./scripts/netem-integration.sh ./bin/autocar
```

该特权套件要求 Linux、nft-backed `iptables`（`iptables --version` 包含
`(nf_tables)`）和 `ethtool`；legacy iptables backend 会被明确拒绝。

netem 套件的背景随机损失由两端 `tc netem` 出口 qdisc 生成。pacing 丢包证明
改用 nft-backed iptables，在接收端 INPUT 对每 N 个符合条件的、长度至少 1,000 字节的
QUIC UDP 数据报丢弃 1 个：上传在 relay INPUT，下载在 client INPUT。它不模拟
ACK/握手小包损失，但既保持方向语义，也避免 sender OUTPUT `DROP` 让 nft-backed
iptables 下的 UDP `sendmsg` 直接返回 `EPERM`。有损阶段只硬验证协商、sender、计数和
传输可进展；fixed-rate 精度使用另一个无确定性丢包的阶段。CI 不把一次 runner
的 adaptive/Reno 吞吐胜负当作算法证明。详见 [基准说明](docs/BENCHMARK.md)。

`scripts/` 中：

- `check-dependency-boundary.sh` 拒绝已知 Hysteria/apernet 模块、local replace 和已知外部源码目录进入构建图；
- `docker-integration.sh` 在隔离容器网络中验证 QUIC、TLS、自动回退、`doctor`、错误令牌拒绝和非 root 只读运行；
- `govulncheck.sh` 安装固定版本的扫描器并检查可达漏洞；
- `netem-integration.sh` 创建 Linux network namespace、延迟/丢包链路并保存诊断工件。

更多文档：[加速机制](docs/ACCELERATION.md)、[架构](docs/ARCHITECTURE.md)、[协议](docs/PROTOCOL.md)、[部署](docs/DEPLOYMENT.md)、[基准](docs/BENCHMARK.md)、[安全](SECURITY.md)。

## License

AutoCAR 使用 MIT 许可证。实际构建依赖及其许可见自动生成的 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
