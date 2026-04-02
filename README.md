# FNP

![ict](./imgs/ict.jpg)

## 架构


### 后端（FNP Daemon）
- 网络接口层：物理网卡、虚拟网卡（如TAP设备）等。统一抽象为网络接口，提供数据包的发送和接收功能。
    - id：唯一标识符
    - name：接口名称
    - type：接口类型（物理、tap）
    - MAC地址：只支持一个MAC地址
    - IP地址列表：支持多个IP地址
    - 默认网关：IP地址+出口设备ID

- 采用弱主机模型，允许接口接收目的地址为本机IP（可能是别的接口的IP）的数据包。

## 路由说明

详细说明见 [doc/routing.md](./doc/routing.md)。

当前实现要点：

- 每个 `network.devices[].ifaddrs[]` 会自动生成一条直连路由
- `network.routes[]` 用于补充静态路由和默认路由
- 选路时先按最长前缀匹配，再按 `priority` 比较；数值越大优先级越高
- `network.routes[]` 未显式配置 `priority` 时，默认优先级高于自动生成路由
- 收包时“是否是本机数据包”不依赖最长前缀路由表，而是精确匹配本地 `ifaddr`
