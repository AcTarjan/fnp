# 后续工作内容

## TODO: FNP优化
- 将worker的tx_ring放到fnp_device，每队列一个tx_ring里, 将send_data_to_net函数的从tx_ring取包发送的逻辑移到fnp_device ops的发送函数里
- worker的send_data_to_net改为遍历所有fnp_device，调用每个fnp_device的发送函数
- fnp-api接口中，evntfd+polling模式中，直接从fsocket的rx_ring burst取包，然后调用fnp_handler_func来处理，处理完毕后，如果这次burst取到数据包了，就不清除evntfd的事件，继续唤醒epoll，进行下一次polling处理；如果这次burst没有取到数据包了，就清除evntfd的事件，设置停止轮询（还需要再检查rx_ring中是否还有数据包，有可能burst后设置polling标志前，新入队一个数据包并查询发现还在polling，就没有触发eventfd），等下次后端再触发eventfd（需要检查这个逻辑是否会存在漏包的情况，还可以优化吗）
- 感觉当前有很多不必要的判断，减少不必要的判断，并使用likely和unlikely优化分支预测
- 检查当前ARP的流程是否合理，是否存在性能瓶颈，是否可以优化
- 对于Connected Socket（远端地址确定），增加相关缓存，避免路由、ARP等查询
- 其他性能优化，如减少锁的使用，减少内存分配等

## TODO: FNP功能完善
- 支持Tun设备，提供Tun设备的创建、配置和数据发送/接收的功能
- 支持TCP协议，提供TCP连接的建立、数据发送/接收和连接关闭的功能
- 支持QUIC协议，提供QUIC连接的建立、数据发送/接收和连接关闭的功能
- 支持应用层协议，如HTTP、DNS等，提供相应的处理逻辑和接口

## TODO: 实现fnp-test-tool
- 在test/fnp目录下利用C实现测试工具fnp-test-tool
- 支持验证UDP通信功能：客户端和服务端功能，节点内通信和节点间通信，非连接和Connected UDP
- 如何测试PPS和时延：本地和远端通信，接收和发送
- 支持测试结果的统计和分析，输出PPS和时延的统计数据
- 后续可能还需要支持Tun、TCP和QUIC的测试
- 可以将代码放在不同的文件里，方便维护和扩展
- 我应该如何设计和实现这个工具


## TODO: 部署和使用优化
- fnp-daemon部署：依赖DPDK库，如何解决，可以将DPDK库编译进fnp-daemon吗
- fnp-deamon可以做成镜像，以容器的形式运行吗
- fnp-api使用：同样依赖DPDK库，如何解决，可以将DPDK库编译进fnp-api吗

## TODO: FNP运维支持
- Web界面：提供一个Web界面，
- 查看和管理FNP的Socket、各个表（路由表、ARP表等）、工作线程等
- 查看流量：每Socket、节点、工作线程等不同维度的流量、丢包统计和分析
- 配置：修改配置，如路由表，ARP表
- 如何实现，通过什么接口，直接在fnp-daemon里实现一个简单的HTTP Server，提供REST API接口，前端通过这些接口获取数据和修改配置，这样就不需要额外的组件了

