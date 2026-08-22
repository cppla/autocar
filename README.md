<p align="center">
  <img src="docs/assets/autocar-logo.svg" width="720" alt="AutoCAR — secure dual-ended accelerator">
</p>

<h1 align="center">AutoCAR</h1>

<p align="center">安全、可测量的 Go 双端自适应网络加速器</p>

<p align="center">
  <a href="https://github.com/cppla/autocar/actions/workflows/ci.yml"><img src="https://github.com/cppla/autocar/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/cppla/autocar/actions/workflows/codeql.yml"><img src="https://github.com/cppla/autocar/actions/workflows/codeql.yml/badge.svg" alt="CodeQL"></a>
  <a href="https://github.com/cppla/autocar/actions/workflows/netem.yml"><img src="https://github.com/cppla/autocar/actions/workflows/netem.yml/badge.svg" alt="netem integration"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-22c55e.svg" alt="MIT License"></a>
</p>

AutoCAR 在本地提供 SOCKS5、HTTP 和 HTTPS Proxy，在远端安全地解析域名并连接目标。默认链路采用 Hysteria v2.12.1 的 HTTP/3-over-QUIC 核心；每个方向独立使用真实的 BBRv1，或在双方明确配置带宽后使用 Brutal。UDP 不可达时，新建 TCP 流会自动切换到独立的 TLS 1.3/TCP 回退链路。

它是 split proxy，不把原始 TCP 包套进 UDP，因此不会产生 TCP-over-TCP 的双重可靠传输。目标是改善高 RTT、随机丢包、短连接和多并发场景；稳定、低时延的直连仍可能更快，请始终在真实路径上测量。

## 已实现的加速机制

| 来源/目标 | AutoCAR 中的实现 | 边界 |
| --- | --- | --- |
| Hysteria v2 | 基于官方 core v2.12.1 的可审计安全加固 fork、HTTP/3 多流、QUIC DATAGRAM、Fast Open、Chrome QUIC 指纹、HTTP/3 cover、可选 Salamander | 不包含实验性的 Gecko、Mimic、端口跳跃或 TUN/TProxy |
| BBR | delivery-rate 与 min-RTT/BDP 模型、pacing，以及 `STARTUP → DRAIN → PROBE_BW → PROBE_RTT`；支持 conservative/standard/aggressive profile | 这是 Hysteria 的 **BBRv1**，不是 Linux 内核 BBRv2/BBRv3 |
| ServerSpeeder/LotServer 的公开目标 | 双端独立发送控制、对端 ACK/RTT/loss 反馈、RFC 9002 packet/time threshold、PTO、热连接拥塞状态复用 | 没有复制 Zeta-TCP 的专有逐包概率算法，也不是内核透明 TCP、FEC 或包复制 |
| 高丢包固定带宽 | 双方协商 `min(发送端上限, 接收端上限)` 后启用 Brutal；根据 ACK/loss 采样补偿并 pacing | 必须显式填准确带宽；会争抢共享链路，默认关闭 |

默认值是 `bbr + standard`，客户端上下行带宽均为 `0`，且服务端默认忽略客户端带宽提示，所以不会无意启用 Brutal。详细机制、参数和诚实的声明边界见 [加速设计](docs/ACCELERATION.md)。

Fast Open 默认关闭；只有显式设置 `--fast-open` 才会让首批应用数据与远端拨号响应重叠。这样能减少一次等待，但目标拒绝等错误可能延迟到第一次读取时才返回。

## 代理与安全

- SOCKS5：CONNECT 和 UDP ASSOCIATE；UDP 通过 QUIC DATAGRAM 双向传输。
- HTTP Proxy：absolute-form HTTP 和 CONNECT。
- HTTPS Proxy：本地代理监听器自身使用 TLS 1.3。
- 隧道安全：TLS 1.3、正常 X.509 SAN/链验证、强制共享令牌、可选 mTLS；不存在 `skip verify` 开关。
- 远端出口：域名由服务端解析，每个 TCP/UDP 目标都经过端口、CIDR、特殊用途地址及 DNS rebinding/SSRF 检查，只使用已批准的数字 IP。
- 资源防护：握手期/已接受的 QUIC 连接、TCP handler、UDP session、双向/单向 stream、HTTP 头和出口 socket 均有硬上限；连接、TCP handler 与 UDP session 还具有跨 QUIC 会话的来源配额（IPv4 地址或 IPv6 `/64`）。TLS/TCP 回退从 accept 到中继结束也有独立的全局与来源连接配额。未认证连接与 TCP 请求头有 deadline，恶意 UDP 分片在分配重组状态前即受限。
- 可达性：QUIC 失败后对新流使用真实 TLS/TCP，并通过熔断冷却避免 UDP 黑洞造成重复等待。
- 抗主动探测：默认未认证请求表现为普通 HTTP/3 页面，客户端启用 Chrome QUIC 指纹；受限网络可选择 Salamander 包混淆。

TLS 保护机密性、完整性和服务端身份；应用仍应使用 HTTPS、SSH 等端到端协议，因为中继知道目标地址，也能看到目标侧明文。网络观察者仍可能看到端点 IP、流量大小和时序。HTTP/3 cover、Salamander 与 TCP 回退提高抗误识别和可达性，但项目不承诺“不可检测”或“永不封锁”。

## 快速开始

需要 Go 1.25 或更高版本。

```bash
git clone https://github.com/cppla/autocar.git
cd autocar
go build -trimpath -o autocar ./cmd/autocar
```

在服务端生成令牌和包含真实域名/IP SAN 的证书：

```bash
./autocar token --out token
./autocar cert \
  --hosts relay.example.com,203.0.113.10 \
  --cert server.crt \
  --key server.key
```

通过可信带外通道把 `token` 与 `server.crt` 复制到客户端；`server.key` 只留在服务端。启动服务端（UDP 与 TCP 可使用相同端口号）：

`autocar cert` 生成与默认 Chrome QUIC 指纹兼容的 ECDSA P-256 证书。若使用外部证书，应选择 ECDSA P-256/P-384 或 RSA；Ed25519 服务端证书需要所有 Hysteria 客户端显式设置 `--disable-chrome-parrot`，否则 TLS 握手会失败并给出提示。

```bash
./autocar server \
  --listen :443 \
  --tcp-listen :443 \
  --cert server.crt \
  --key server.key \
  --token-file token
```

启动客户端：

```bash
./autocar client \
  --server relay.example.com:443 \
  --ca server.crt \
  --token-file token
```

默认入口：

| 入口 | 地址 | 示例 |
| --- | --- | --- |
| SOCKS5 TCP/UDP | `127.0.0.1:1080` | `curl --proxy socks5h://127.0.0.1:1080 https://example.com` |
| HTTP Proxy | `127.0.0.1:8080` | `curl --proxy http://127.0.0.1:8080 https://example.com` |
| HTTPS Proxy | 默认关闭 | 使用 `--https`、`--proxy-cert`、`--proxy-key` 开启 |

`socks5h` 会把域名交给远端解析。AutoCAR 不伪造目标证书，也不解密应用到目标站点之间的 HTTPS。

## 选择 BBR 或 Brutal

一般部署直接使用默认 BBR。可按链路偏好选择 profile：

```bash
# 共享链路更保守
./autocar client [其他参数] --bbr-profile conservative

# Startup 更激进；必须先在自己的链路做公平性与排队延迟测试
./autocar client [其他参数] --bbr-profile aggressive
```

只有已知真实链路容量时才配置 Brutal。官方客户端会在每个方向取声明值与服务端协商上限中的较小值：

```bash
# 服务端：每个认证会话最高上传 100 Mbit/s、下载 300 Mbit/s
./autocar server [其他参数] \
  --allow-client-bandwidth \
  --max-upload-mbps 100 \
  --max-download-mbps 300

# 客户端：本地链路实测上限
./autocar client [其他参数] \
  --upload-mbps 80 \
  --download-mbps 250
```

服务端只有显式设置 `--allow-client-bandwidth` 且同时提供两个有限协商上限时才接受 Brutal 提示；默认会强制 BBR/Reno。配置高于实际容量会造成排队、丢包和浪费。上述值是协议协商与 pacing 目标，不是针对恶意客户端的流量整形器；需要不可绕过的限速时，应在主机或云网络层配置 policer。Brutal 不是 Reno/CUBIC 公平模式，共享网络应保留默认 BBR。

## HTTP/3 cover 与 Salamander

默认模式是标准 HTTP/3 cover：错误令牌或普通探测会得到中性网页，客户端模拟 Chrome QUIC 的可见参数。若 UDP 被按 QUIC 特征干扰，可在两端配置同一条独立强密码：

```bash
./autocar token --out obfs-password

./autocar server [其他参数] --obfs-password-file obfs-password
./autocar client [其他参数] --obfs-password-file obfs-password
```

也可通过 `AUTOCAR_OBFS_PASSWORD` 提供。Salamander 只是包级混淆，真正的认证与加密仍由 TLS 1.3 完成。启用后线上形态不再是标准 HTTP/3，因此应在“HTTP/3 cover”和“Salamander”之间按网络环境选择，而不是同时宣传两种外观。

## 本地代理认证与 mTLS

无认证入口只能绑定环回。SOCKS5 用户名密码和 HTTP Basic 在本地这一跳是明文；跨主机使用应开启 HTTPS Proxy，不要把明文入口直接暴露到公网。

```bash
export AUTOCAR_PROXY_USER=alice
export AUTOCAR_PROXY_PASSWORD='replace-with-a-long-random-secret'

./autocar client [中继参数] \
  --socks 127.0.0.1:1080 \
  --http 127.0.0.1:8080
```

客户端信任方式必须二选一：`--ca <PEM>` 固定私有 CA/自签名证书，或显式使用 `--system-roots`。证书名称与连接地址不一致时设置 `--server-name`。mTLS 使用服务端 `--client-ca` 与客户端 `--client-cert/--client-key`；共享令牌仍保留为第二层授权。

## 出口策略

默认拒绝环回、私网、链路本地、多播、未指定地址、IANA 特殊用途地址，以及端口 `25,465,587`。`--allow-private` 仅允许 RFC1918/ULA/CGNAT，仍不会开放环回或云元数据等特殊地址。`--deny-cidrs` 与 `--deny-ports` 可进一步收紧策略。

生产环境还应使用主机/云防火墙限制中继 UDP/TCP 端口，给 UDP 设置每源速率与突发上限，并优先启用 mTLS。完整 systemd、容器、防火墙和升级说明见 [部署指南](docs/DEPLOYMENT.md)。

## 兼容性

当前默认 QUIC wire protocol 是 Hysteria v2.12.1。`--transport=hy2` 与 `--transport=quic` 等价；旧 AutoCAR 自定义 QUIC v1 可临时使用客户端 `--transport=legacy-quic` 配合服务端 `--quic-engine=legacy`。TLS/TCP fallback 继续使用 AutoCAR protocol v1。一次 UDP 端口不能同时运行两种 QUIC wire protocol，升级时必须协调两端或使用不同端口。

## 性能验证

内置基准会在相同目标、负载和链路条件下比较 direct、hy2/QUIC 与 TLS：

```bash
./autocar bench-server

./autocar bench-client \
  --transport direct \
  --target target.example:9000 \
  --bytes 8388608 --iterations 7 --warmup 2 --json

./autocar bench-client \
  --transport quic \
  --server relay.example.com:443 \
  --ca server.crt --token-file token \
  --target target.example:9000 \
  --bytes 8388608 --iterations 7 --warmup 2 --json
```

Linux `netem` 套件分别验证客户端上传与中继下载在高 RTT/丢包下 BBR 相对 Reno 的收益、Brutal 实际协商/发送、热连接短流收益、错误证书/令牌、UDP→TLS 回退，以及抓包中不存在明文 sentinel：

```bash
make build
sudo ./scripts/netem-integration.sh ./bin/autocar
```

`make release` 生成四个平台的发布归档；每个归档都同时包含可执行文件、AutoCAR 的 `LICENSE` 和完整的 `THIRD_PARTY_NOTICES.md`，不会发布缺少许可文件的裸二进制。

CI 中的窄场景速度门只证明被测试的机制有效，不代表所有生产网络都会加速。方法、指标和扩展矩阵见 [基准说明](docs/BENCHMARK.md)。

## 开发

```bash
go test ./...
go test -race ./...
go vet ./...
```

- [加速机制与边界](docs/ACCELERATION.md)
- [架构](docs/ARCHITECTURE.md)
- [Wire protocol](docs/PROTOCOL.md)
- [部署指南](docs/DEPLOYMENT.md)
- [基准方法](docs/BENCHMARK.md)
- [安全策略](SECURITY.md)
- [第三方许可](THIRD_PARTY_NOTICES.md)

## License

AutoCAR 使用 MIT 许可证，见 [LICENSE](LICENSE)。实际链接的全部 Go 依赖及其根级许可、通知和专利声明见自动生成的 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
