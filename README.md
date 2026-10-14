# open-tunnel

`open-tunnel` 是一个使用 UDP 在多个客户端之间转发 IPv4 数据包的轻量级隧道程序。服务端负责维护客户端会话，并将隧道数据包转发给目标客户端；客户端通过系统 TUN 网卡收发数据。

## 功能

- 基于 UDP 的客户端与服务端通信。
- 支持为服务端配置用户名和密码认证。
- 客户端通过心跳维持会话，服务端会清理超时会话。
- 可在客户端启动时配置 TUN 网卡的 IPv4 地址。

## 环境要求

- Go 1.26.8 或兼容版本，用于从源码构建。
- Linux 客户端需要启用 TUN，并具有创建 TUN 网卡和配置网卡的权限（通常使用 `root` 或 `CAP_NET_ADMIN`）；配置 `--ip` 时还需要 `ip` 命令。
- 服务端 UDP 端口需要允许客户端访问。

## 构建

```sh
git clone https://github.com/Li-giegie/open-tunnel.git
cd open-tunnel
go build -o open-tunnel .
```

也可以用 `go run .` 直接运行。查看命令和参数：

```sh
./open-tunnel --help
./open-tunnel server --help
./open-tunnel client --help
```

## 使用

### 1. 启动服务端

在可被客户端访问的主机上运行：

```sh
./open-tunnel server --addr 0.0.0.0:9000 --users 'alice:change-me'
```

`--users` 可包含多个账号，以逗号分隔，例如 `alice:secret,bob:another-secret`。省略该参数时，服务端不校验用户名和密码。

### 2. 启动客户端

在每台客户端主机上分别运行，并为每台主机分配唯一的隧道 IPv4 地址。以下示例中，服务端地址为 `198.51.100.10:9000`：

```sh
sudo ./open-tunnel client \
  --addr 198.51.100.10:9000 \
  --username alice \
  --password change-me \
  --ip 10.20.0.2/24
```

另一台客户端使用相同的服务端和凭据，但应使用不同的地址，例如：

```sh
sudo ./open-tunnel client \
  --addr 198.51.100.10:9000 \
  --username alice \
  --password change-me \
  --ip 10.20.0.3/24
```

传入 `--ip` 后，客户端会尝试为 `tun0` 添加该 IPv4 地址并启用网卡。地址应在各客户端之间保持唯一；将客户端配置在同一隧道子网后，可通过隧道 IP 相互通信。

## 命令行参数

### `server`

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `--addr` | `0.0.0.0:9000` | UDP 监听地址 |
| `--users` | 空 | 逗号分隔的 `用户名:密码` 列表；为空时不启用认证 |
| `--health-interval` | `1m` | 服务端检查会话健康状态的间隔 |
| `--health-timeout` | `2m` | 客户端无活动超过此时间后清理会话 |

### `client`

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `--addr` | `127.0.0.1:9000` | 服务端 UDP 地址 |
| `--username` | 空 | 认证用户名 |
| `--password` | 空 | 认证密码 |
| `--ip` | 不设置 | 可选的 TUN 网卡 IPv4 地址和前缀，例如 `10.20.0.2/24` |
| `--keepalive` | `15s` | 客户端发送心跳的间隔 |
| `--timeout` | `2m` | 客户端等待服务端响应的超时时间 |

## 安全说明

当前实现通过 UDP 明文传输认证信息和隧道数据，不提供加密或完整性保护。请仅在可信网络或受保护的网络通道中使用，并避免将未启用认证的服务端暴露到不可信网络。命令行密码也可能被本机进程信息读取。

## 许可证

[MIT License](./LICENSE)
