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


def run_client(target_ip=DEFAULT_CLIENT_IP, target_port=DEFAULT_CLIENT_PORT, message="Hello, UDP!"):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(message.encode(), (target_ip, target_port))
    print(f"已向 {target_ip}:{target_port} 发送数据包，内容：{message}")


def main():
    parser = argparse.ArgumentParser(description="UDP客户端/服务端样例")
    parser.add_argument('--mode', choices=['server', 'client'], required=True, help='运行模式: server 或 client')
    parser.add_argument('--ip', type=str, help='服务端监听或客户端目标IP')
    parser.add_argument('--port', type=int, help='服务端监听或客户端目标端口')
    parser.add_argument('--message', type=str, help='客户端发送内容')
    args = parser.parse_args()

    if args.mode == 'server':
        ip = args.ip if args.ip else DEFAULT_SERVER_IP
        port = args.port if args.port else DEFAULT_SERVER_PORT
        run_server(ip, port)
    else:
        ip = args.ip if args.ip else DEFAULT_CLIENT_IP
        port = args.port if args.port else DEFAULT_CLIENT_PORT
        msg = args.message if args.message else "Hello, UDP!"
        run_client(ip, port, msg)


if __name__ == '__main__':
    main()
