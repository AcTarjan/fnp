import socket
import argparse

DEFAULT_SERVER_IP = '192.168.66.66'
DEFAULT_SERVER_PORT = 16666
DEFAULT_CLIENT_IP = '192.168.66.88'
DEFAULT_CLIENT_PORT = 18888


def run_server(ip=DEFAULT_SERVER_IP, port=DEFAULT_SERVER_PORT):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((ip, port))
    print(f"UDP服务端监听 {ip}:{port}")
    while True:
        data, addr = sock.recvfrom(4096)
        print(f"收到来自{addr}的数据包，大小：{len(data)} 字节，内容：{data}")
        reply = b"hello from linux udp server!"
        sock.sendto(reply, addr)
        print(f"已回送数据包给{addr}，内容：{reply}")


def run_client(target_ip=DEFAULT_CLIENT_IP, target_port=DEFAULT_CLIENT_PORT,
               message="Hello, UDP!", bind_ip=None, bind_port=None,
               wait_reply=False, timeout=3.0):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if bind_ip is not None or bind_port is not None:
        sock.bind((bind_ip if bind_ip else "", bind_port if bind_port else 0))
        print(f"UDP客户端绑定 {(bind_ip if bind_ip else '0.0.0.0')}:{sock.getsockname()[1]}")

    if wait_reply:
        sock.settimeout(timeout)

    sock.sendto(message.encode(), (target_ip, target_port))
    print(f"已向 {target_ip}:{target_port} 发送数据包，内容：{message}")

    if wait_reply:
        data, addr = sock.recvfrom(4096)
        print(f"收到来自{addr}的回包，大小：{len(data)} 字节，内容：{data}")


def main():
    parser = argparse.ArgumentParser(description="UDP客户端/服务端样例")
    parser.add_argument('--mode', choices=['server', 'client'], required=True, help='运行模式: server 或 client')
    parser.add_argument('--ip', type=str, help='服务端监听或客户端目标IP')
    parser.add_argument('--port', type=int, help='服务端监听或客户端目标端口')
    parser.add_argument('--message', type=str, help='客户端发送内容')
    parser.add_argument('--bind-ip', type=str, help='客户端本地绑定IP')
    parser.add_argument('--bind-port', type=int, help='客户端本地绑定端口')
    parser.add_argument('--wait-reply', action='store_true', help='客户端发送后等待一次回包')
    parser.add_argument('--timeout', type=float, default=3.0, help='客户端等待回包超时时间，单位秒')
    args = parser.parse_args()

    if args.mode == 'server':
        ip = args.ip if args.ip else DEFAULT_SERVER_IP
        port = args.port if args.port else DEFAULT_SERVER_PORT
        run_server(ip, port)
    else:
        ip = args.ip if args.ip else DEFAULT_CLIENT_IP
        port = args.port if args.port else DEFAULT_CLIENT_PORT
        msg = args.message if args.message else "Hello, UDP!"
        run_client(ip, port, msg, args.bind_ip, args.bind_port, args.wait_reply, args.timeout)


if __name__ == '__main__':
    main()
