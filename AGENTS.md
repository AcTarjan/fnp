# AGENTS.md

## 项目定位

`fnp` 是一个基于 DPDK 的用户态 TCP/IP 协议栈，采用前后端分离架构：

- 前端是动态库 `fnp-api`，由业务进程加载。
- 后端是宿主机上的守护进程 `fnp-daemon`。
- 正常运行时通过 DPDK 接管物理网卡。
- 测试态现在可以通过 DPDK TAP `vdev` 与内核协议栈互通，参考 [fnp-tap.yaml](/root/fnp/conf/fnp-tap.yaml) 和 [setup-tap-test.sh](/root/fnp/deploy/setup-tap-test.sh)。

当前仓库里，UDP 路径最完整；TCP 已有真实状态机和数据通路；QUIC 后端代码很多，但前端公开 API 还没有完整接通。

## 先信什么，后信什么

这个仓库有不少历史样例和过期脚本。发生冲突时，建议按下面的优先级判断“真实行为”：

1. 根目录 [CMakeLists.txt](/root/fnp/CMakeLists.txt)
2. `inc/` 下的当前头文件，以及被 `CMakeLists.txt` 实际编译进目标的 `src/api/`、`src/common/`、`src/daemon/`
3. [main.go](/root/fnp/src/daemon/go/main.go) 定义的配置文件 schema，与 [fnp.yaml](/root/fnp/conf/fnp.yaml) / [fnp-tap.yaml](/root/fnp/conf/fnp-tap.yaml)
4. `test/`、`src/demo/`、`deploy/`
5. [README.md](/root/fnp/README.md)

`README.md` 目前几乎没有有效技术信息，不要把它当作项目说明书。

## 目录地图

- `inc/`
  - 对外公开 API、公共类型、错误码。
  - 这里的 `fsockaddr_t` 使用网络序。
- `src/api/`
  - 前端动态库实现。
  - 负责 secondary process 初始化、向 daemon 注册、发起 socket 创建/accept/close 请求。
- `src/common/`
  - 前后端共享的数据结构和基础设施。
  - 重点看 `fnp_socket.h`、`fnp_frontend.h`、`fnp_ring.*`、`fnp_msg.*`。
- `src/daemon/`
  - 后端守护进程。
  - `fnp_context.*` 初始化全局上下文。
  - `fnp_master.*` 管理 frontend、`rte_mp` action、eventfd。
  - `fnp_worker.*` 负责 worker lcore 的轮询主循环。
  - `fsocket.*` 管理共享 socket、socket 表、本地直连路径。
  - `iface/`、`ether/`、`arp/`、`ip/`、`icmp/`、`udp/`、`tcp/` 是主协议路径。
  - `picoquic/` 是大块 QUIC 实现，绝大多数是上游/移植代码。
- `src/daemon/go/`
  - Go 写的 YAML 解析器，编译成 `libfnp-conf.a` 给 C 使用。
- `conf/`
  - daemon 配置模板目录。
- `dep_libs/`
  - 历史预编译依赖目录。
  - 当前构建已经改为直接使用 `deps/` 下的产物，不再依赖它。
- `deps/dpdk/`、`deps/picotls/`
  - 第三方依赖的源码、构建脚本和模板。
  - 当前运行时 DPDK 安装前缀默认是 `/opt/dpdk`。
- `test/`
  - 各种实验、压测、对比样例。
  - 很多代码已经落后于当前 API。
- `deploy/`
  - 环境和部署脚本，存在新旧混杂。
- `doc/`
  - 参考资料，不参与构建。

## 当前实际架构

### 进程模型

- `fnp-daemon` 是 DPDK primary process。
- `fnp-api` 初始化时走 DPDK secondary process，`--file-prefix=fnp` 必须和 daemon 对齐。
- daemon 主 lcore 跑 `fnp_master_loop()`。
- worker lcore 跑 `fnp_worker_loop()`。

### 前后端通信模型

前后端不是普通 socket RPC，而是下面这套组合：

- `rte_mp_request_sync` / `rte_mp_action_register`
  - 用于 frontend 注册、创建 socket、accept、close。
- 共享 `fsocket_t*`
  - 由 daemon 创建，回给 frontend 使用。
- 共享 `fnp_ring_t`
  - 承载应用数据或待 accept 的连接。
- eventfd
  - 前端发数据后通知后端。
  - 后端有数据可读时通知前端。
- 每 frontend 一个专属 mempool
  - 在 `register_frontend_action()` 中由 daemon 创建。

注意：应用拿到的“socket fd”本质上是 `rx_efd_in_frontend`。

### worker 主循环

`src/daemon/fnp_worker.c` 里的 worker 循环当前是纯轮询模型：

1. 从 NIC `rx_burst`
2. 进入 `ether_recv_mbuf()`
3. 定时执行 `rte_timer_manage()`
4. 轮询被加入 `polling_table` 的协议 socket
5. 从 `tx_ring` 向 NIC `tx_burst`

目前 `fnp_worker_add_fsocket()` 直接把 socket 固定分配到 worker 0，没有负载均衡。

## 数据通路

### RX

NIC -> `ether_recv_mbuf()` -> `ipv4_recv_mbuf()` -> UDP/TCP/ICMP -> `fsocket_enqueue_for_app()` -> frontend 的 `rx` ring -> 应用 `fnp_recv*`

### TX

应用 `fnp_send*` -> frontend 的 `tx` ring -> eventfd 通知 master -> socket 被加入 worker polling -> UDP/TCP 封包 -> IPv4/ARP/Ether -> NIC

### 本地优化路径

项目里已经有两条“本地不出网卡”的路径：

- Local Forwarding Path
  - 只在 UDP 上使用。
  - 远端 IP 是本机 IP，但不是严格的直连双端配对时，由 daemon 中转。
- Local Direct Path, LDP
  - 在 `create_fsocket()` 时，如果发现本地 socket 对端也是本机并且能配对，直接交换/共享 ring 和 eventfd。
  - `polling_worker == fnp_worker_count` 被当作 LDP 特殊标记。
  - QUIC 明确不走 LDP。

LDP 的 ring 和 eventfd 可能由两端共享，改销毁逻辑时一定要同时看 [src/daemon/fsocket.c](/root/fnp/src/daemon/fsocket.c)。

## 协议层现状

### UDP

UDP 是当前最可信的主路径：

- 支持网络发送接收。
- 支持本地转发。
- 支持本地直连。
- `test/fnp/fnp_udp_client.c` 里的注释比样例本身更有参考价值。

### TCP

TCP 已经不是空壳，至少包含：

- listen / SYN / SYN-ACK / ACK
- established 数据收发
- FIN 关闭路径
- 重传定时器
- 延迟 ACK
- out-of-order tree
- CUBIC 拥塞控制骨架

但它还不是“收尾完成”的状态，尤其要注意：

- close 路径仍有 TODO
- worker/polling 和 socket 生命周期存在未完全打磨的地方
- 很多测试样例已经和当前 API 脱节

### QUIC

QUIC 现状要分开看：

- 后端代码很多，`src/daemon/picoquic/` 已经包含大块 picoquic 代码和 FNP 适配。
- `quic_create_context()` 还会在后端内部创建一个 UDP socket 作为承载。
- 但前端 QUIC API 没有真正接通到当前构建：
  - [inc/fnp.h](/root/fnp/inc/fnp.h) 里大部分 QUIC API 还是注释状态。
  - [src/api/fnp_quic.c](/root/fnp/src/api/fnp_quic.c) 存在，但没有被加入 `fnp-api` target。
  - `src/demo/` 里的 QUIC demo 不能当作当前可编译、可运行的真相。

### 路由 / ARP / ICMP

- ARP 是可工作的，有缓存表、请求、回复、pending 队列和重试定时器。
- ICMP 支持 echo reply 和 UDP 端口不可达。
- 真正的“路由表”还没有做起来：
  - [src/daemon/ip/route.c](/root/fnp/src/daemon/ip/route.c) 是空的。
  - 当前发送路径实际依赖 `src/daemon/iface/fnp_iface.c` 中的子网/网关判断。

## 已知不一致和坑点

这些点后续代理非常容易踩：

- [inc/fnp.h](/root/fnp/inc/fnp.h) 注释说 TCP/UDP client 的本地地址可以是 0，但当前后端 `create_fsocket()` 会先 `lookup_iface(local->ip)`，也就是本地 IP 必须已经配置在某个 iface 上。
- [deploy/fnp.yaml](/root/fnp/deploy/fnp.yaml) 已删除；兼容模板应以 [fnp.yaml](/root/fnp/conf/fnp.yaml) 为准。
- [src/daemon/main.c](/root/fnp/src/daemon/main.c) 现在支持可选命令行参数传入配置文件路径；不传时仍默认找 `fnp.yaml`。
- DPDK 现在默认从 `/opt/dpdk` 取头文件和库，库目录会优先选择 `lib/${CMAKE_LIBRARY_ARCHITECTURE}`，其次才是 `lib64` 或 `lib`。
- picotls 现在默认从 [deps/picotls](/root/fnp/deps/picotls) 取头文件和库，需要先跑 [deps/picotls/build.sh](/root/fnp/deps/picotls/build.sh)。
- `conf` 解析库现在来自 [src/daemon/go](/root/fnp/src/daemon/go) 下的静态库 `libfnp-conf.a`，不是旧的 `dep_libs/conf/libfnp-conf.so`。
- 很多 `test/` 和 `src/demo/` 样例使用了旧签名：
  - 把 `fnp_recv` 当成“直接返回 mbuf”的接口
  - 把 `fnp_create_socket` 当成“返回 `fsocket_t*`”的接口
  - 调用当前头文件里并未导出的 QUIC API
- `src/common/fnp_msg.*` 和 `fchannel` 更像一套早期/旁路消息机制；当前主路径还是 `rte_mp_* + ring + eventfd`。
- TAP 测试路径已经可用，但目前更适合单 worker、本机联调。
- worker 的 `mbuf_pool_size` / `clone_pool_size` / `rx_pool_size` 建议使用 `2^n - 1`，`tx_ring_size` 必须是 2 的幂；模板已经按这个约束修正。

## 构建和运行建议

### 当前 CMake 实际编译的目标

根目录 [CMakeLists.txt](/root/fnp/CMakeLists.txt) 当前直接编译：

- `fnp-daemon`
- `fnp-api`

没有直接编进主构建的内容包括：

- `src/api/fnp_quic.c`
- `src/demo/*`
- 大多数 `test/*`

如果你改了某个文件，先确认它是不是根本没有参与当前构建。

### 依赖准备

通常需要先准备：

1. DPDK，且安装位置要和 `CMakeLists.txt` 一致
2. `src/daemon/go/libfnp-conf.a`
   - 由 [build.sh](/root/fnp/src/daemon/go/build.sh) 生成
3. `deps/picotls`
   - 由 [deps/picotls/build.sh](/root/fnp/deps/picotls/build.sh) 生成
4. OpenSSL、libnuma、libpcap

### 常见构建顺序

可以按下面的思路：

1. 先生成 `libfnp-conf.a`
2. 再生成 `deps/picotls` 里的头文件和静态库
3. 确认 DPDK 已经安装到 `/opt/dpdk`
4. 准备一份兼容的 `fnp.yaml`，或者直接在启动参数里传配置文件路径
5. 配置和编译 CMake

### 运行目录

daemon 不传参时会在当前工作目录找 `fnp.yaml`。更稳妥的做法通常是直接传配置文件路径：

- `./build/fnp-daemon /root/fnp/conf/fnp.yaml`
- `./build/fnp-daemon /root/fnp/conf/fnp-tap.yaml`

如果仍想走工作目录模式：

- 以 [fnp.yaml](/root/fnp/conf/fnp.yaml) 或 [fnp-tap.yaml](/root/fnp/conf/fnp-tap.yaml) 为模板复制到运行目录
- 再按本机网卡、lcore、gateway 或 TAP 地址修改

## 修改代码时的工作准则

### 共享 ABI 要一起看

下面这些结构是前后端共享的，改一个地方不够：

- `fsocket_t`
- `fnp_frontend_t`
- `fmbuf_info_t`
- `fnp_ring_t`

相关文件分散在：

- [src/common/fnp_socket.h](/root/fnp/src/common/fnp_socket.h)
- [src/common/fnp_frontend.h](/root/fnp/src/common/fnp_frontend.h)
- [src/common/fnp_ring.h](/root/fnp/src/common/fnp_ring.h)
- [src/api/](/root/fnp/src/api)
- [src/daemon/](/root/fnp/src/daemon)

### 注意网络序

公开 API 的地址和端口是网络序。改 socket 创建、报文填充、测试代码时都要保持这一点，否则会出现“能编译、不能通”的假成功。

### 注意 mbuf 私有区

项目大量把元数据塞到 mbuf private area 里：

- `fnp_mbuf_info_t`
- `fmbuf_info_t`
- `tcp_mbufinfo_t`
- QUIC packet/stream data

`FNP_MBUFPOOL_PRIV_SIZE` 是全局约束。改 metadata 结构或新增私有数据时，必须同时检查所有 mbuf pool 创建位置。

### 不要轻易重写 picoquic 目录

`src/daemon/picoquic/` 大部分是上游/移植代码。除非确实要修 QUIC 细节，否则优先在这些边界处做小改动：

- [src/daemon/picoquic/quic.c](/root/fnp/src/daemon/picoquic/quic.c)
- [src/daemon/picoquic/quic_recv.c](/root/fnp/src/daemon/picoquic/quic_recv.c)
- [src/daemon/picoquic/quic_sender.c](/root/fnp/src/daemon/picoquic/quic_sender.c)
- [src/daemon/picoquic/quic_stream.c](/root/fnp/src/daemon/picoquic/quic_stream.c)
- [src/daemon/picoquic/quicctx.c](/root/fnp/src/daemon/picoquic/quicctx.c)

### LDP 和释放逻辑要格外小心

本地直连路径会共享 ring 和 eventfd。处理 socket 关闭、错误回收、frontend 掉线清理时，必须考虑：

- ring 引用计数
- 对端是否还活着
- eventfd 是否被两端共用

先读 [src/daemon/fsocket.c](/root/fnp/src/daemon/fsocket.c)，再改。

## 推荐阅读顺序

新代理上手时，建议按这个顺序读：

1. [CMakeLists.txt](/root/fnp/CMakeLists.txt)
2. [inc/fnp.h](/root/fnp/inc/fnp.h)
3. [src/common/fnp_socket.h](/root/fnp/src/common/fnp_socket.h)
4. [src/common/fnp_frontend.h](/root/fnp/src/common/fnp_frontend.h)
5. [src/common/fnp_ring.c](/root/fnp/src/common/fnp_ring.c)
6. [src/api/fnp_frontend.c](/root/fnp/src/api/fnp_frontend.c)
7. [src/api/fsocket.c](/root/fnp/src/api/fsocket.c)
8. [src/daemon/fnp_context.c](/root/fnp/src/daemon/fnp_context.c)
9. [src/daemon/fnp_master.c](/root/fnp/src/daemon/fnp_master.c)
10. [src/daemon/fnp_worker.c](/root/fnp/src/daemon/fnp_worker.c)
11. [src/daemon/fsocket.c](/root/fnp/src/daemon/fsocket.c)
12. [src/daemon/iface/fnp_iface.c](/root/fnp/src/daemon/iface/fnp_iface.c)
13. [src/daemon/ether/ether.c](/root/fnp/src/daemon/ether/ether.c)
14. [src/daemon/ip/ipv4.c](/root/fnp/src/daemon/ip/ipv4.c)
15. [src/daemon/udp/udp.c](/root/fnp/src/daemon/udp/udp.c)
16. [src/daemon/tcp/](/root/fnp/src/daemon/tcp)
17. `src/daemon/picoquic/`，只在需要改 QUIC 时深入

## 如果要实现 TAP 测试模式

推荐原则：

- 不要把 TAP 特判散落到 TCP/UDP/ARP/ICMP 里。
- 尽量把“物理 NIC”与“TAP 设备”差异收敛在 `iface/` 或一个新的后端适配层。
- 让协议层继续只面向 mbuf 和既有入口：
  - 入方向尽量仍然走 `ether_recv_mbuf()`
  - 出方向尽量复用 `ether_send_mbuf()` 所在抽象边界
- 先明确 TAP 是单独测试后端，还是和 DPDK 物理口共存；不要在实现中把两条路径混成一个不可维护的分支团。

## 测试建议

- 当前最靠谱的 smoke path 是“daemon + UDP”主链路。
- `test/fnp/`、`test/local/`、`test/remote_udp/` 更适合作为历史意图参考，不适合作为当前 API 的权威示例。
- 如果你改了 TCP 或 QUIC，通常需要顺手补一套新的可编译样例或测试，因为现有样例大概率是过期的。
