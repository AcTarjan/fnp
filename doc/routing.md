# FNP 路由说明

本文描述 FNP 当前版本的路由建表、查表、优先级规则，以及收包时如何判断“是否是本机数据包”。

## 1. 总体规则

FNP daemon 初始化时会构建一张简单的内存路由表。当前实现特点是：

- 先根据本地 `ifaddr` 自动生成直连路由
- 再追加配置文件 `network.routes[]` 中的静态路由和默认路由
- 发送时按“最长前缀优先，其次按 `priority` 优先”选路
- 收包时判断“是否是本机包”不走最长前缀查表，而是直接精确匹配本地 IP

## 2. 自动生成的路由

每个 `network.devices[].ifaddrs[]` 都会自动生成一条直连路由，等价语义为：

- `prefix = ifaddr 所在网段`
- `dev = ifaddr 所属设备`
- `next hop = 0`
- `priority = 0`

例如：

```yaml
network:
  devices:
    - name: "eth0"
      ifaddrs:
        - "192.168.136.88/24"
```

会自动生成一条等价于：

```text
192.168.136.0/24 dev eth0 priority 0
```

这条路由用于处理同网段目的地址的发送路径。

## 3. `network.routes[]` 配置字段

当前支持的字段如下：

```yaml
network:
  routes:
    - dst: "10.20.0.0/16"
      dev: "eth0"
      via: "192.168.136.1"
      src: "192.168.136.88"
      priority: 200
```

- `dst`：必填，目标网段，支持标准 CIDR；默认路由可写 `"default"`
- `dev`：必填，出口设备名称
- `via`：可选，下一跳 IPv4 地址
- `src`：可选，显式指定从该设备上的哪个本地 IP 发包
- `priority`：可选，数值越大优先级越高

当前默认值：

- 自动生成的直连路由：`priority = 0`
- `network.routes[]`：如果未显式填写 `priority`，默认取 `100`

因此，在“前缀长度相同”的情况下，`network.routes[]` 默认会优先于自动生成路由。

## 4. 路由项的语义

### 4.1 配置了 `via`

当 `via` 非空时，这是一条网关路由：

- 报文从 `dev` 对应设备发出
- 二层解析对象是 `via`
- `src` 如果未指定，则根据 `via` 所在网段自动挑选该设备上的合适 `ifaddr`

示例：

```yaml
network:
  routes:
    - dst: "10.20.0.0/16"
      dev: "eth0"
      via: "192.168.136.1"
      priority: 200
```

### 4.2 未配置 `via`

当 `via` 为空时，这是一条直连静态路由：

- 报文从 `dev` 对应设备发出
- 二层解析对象是目标 IP 本身
- 常用于“目的网段被视作 on-link”的场景

示例：

```yaml
network:
  routes:
    - dst: "10.20.0.0/16"
      dev: "eth0"
      priority: 150
```

### 4.3 默认路由

`dst: "default"` 只有在同时配置了 `via` 时，才表示真正的默认网关路由。

示例：

```yaml
network:
  routes:
    - dst: "default"
      dev: "eth0"
      via: "192.168.136.1"
```

如果把 `default` 写成不带 `via` 的直连语义，实际效果通常不符合预期。

## 5. 选路优先级

当前发送路径的查表规则是：

1. 先判断目标 IP 是否就是本机 IP
2. 如果不是本机 IP，则在路由表中做最长前缀匹配
3. 如果前缀长度相同，则比较 `priority`
4. 如果 `priority` 也相同，则保留先入表的那条路由

也就是说，优先级顺序是：

1. 前缀长度更长
2. `priority` 更高
3. 同前缀、同优先级时，先加入路由表的项优先

## 6. 自动生成路由与 `network.routes[]` 的关系

初始化顺序仍然是：

1. 自动生成 connected route
2. 再加载 `network.routes[]`

但由于 `network.routes[]` 默认 `priority = 100`，自动生成路由默认 `priority = 0`，所以：

- 更长前缀的静态路由一定优先
- 同前缀长度时，静态路由默认优先于自动生成路由
- 如果你把某条静态路由的 `priority` 显式设为 `0`，那么它和自动生成路由同优先级，最终会保留先入表的自动生成路由

例如：

```yaml
network:
  devices:
    - name: "eth0"
      ifaddrs:
        - "192.168.136.88/24"
  routes:
    - dst: "192.168.136.0/24"
      dev: "eth0"
      via: "192.168.136.1"
```

这时两条路由的前缀长度相同，但静态路由默认优先级更高，所以会优先命中 `network.routes[]` 中这条项。

## 7. 收包时如何判断是不是本机数据包

FNP 当前收包路径并不是“先查最长前缀路由，再决定是不是本机”，而是直接精确匹配本地 IP。

逻辑流程如下：

1. 网卡收到 IPv4 报文
2. 进入 `ipv4_recv_mbuf()`
3. 调用 `ipv4_is_local_packet()`
4. `ipv4_is_local_packet()` 调用 `route_lookup_local(dst_ip)`
5. `route_lookup_local()` 内部直接调用 `lookup_ifaddr(dst_ip)`
6. 如果目标 IP 精确命中某个本地 `ifaddr`，则判定为本机包并继续本地递交
7. 否则当前版本直接丢包，因为 IPv4 forwarding path 还没实现

关键点：

- 这里用的是“本地 IP 精确匹配”
- 不是最长前缀匹配
- 也不依赖 `network.routes[]` 的 `priority`

所以，即使你把同前缀情况下静态路由的优先级调得更高，也不会影响“收到的数据包是否被判定为本机包”。

## 8. 发送时的查表流程

发送路径的逻辑则是：

1. 如果目标 IP 就是本机地址，直接走本地递交
2. 否则查最长前缀路由
3. 命中后得到：
   - 从哪个 `ifaddr` 发送
   - 实际下一跳是谁
   - 建议填哪个源 IP
4. 根据设备类型走 ARP / Ethernet / TAP / TUN 发送路径

简化后可以理解为：

```text
if dst is local IP:
    local deliver
else:
    best route = longest prefix, then highest priority
    next hop = via if configured, else dst
    send via route device
```

## 9. 配置建议

- 同网段直连目的，通常不需要显式配置 `routes`
- 如果你想覆盖自动生成的同前缀直连路由，可以直接在 `network.routes[]` 中写同前缀路由，默认就会生效
- 如果需要更细粒度控制，可以显式配置 `priority`
- 非直连网段通常应显式填写 `via`
- 默认路由必须填写 `via`
- 一个设备上有多个 `ifaddr` 时，建议显式配置 `src`
