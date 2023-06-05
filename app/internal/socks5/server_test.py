import socket
import socks
import os

ADDR = "127.0.0.1"
PORT = 11080


def test_tcp(size, count, it):
    for i in range(it):
        s = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
        s.set_proxy(socks.SOCKS5, ADDR, PORT)

        s.connect(("test_tcp", 12345))
        for j in range(count):
            payload = os.urandom(size)
            s.send(payload)
            rsp = s.recv(size)
            assert rsp == payload
        s.close()


def test_udp(size, count, it):
    for i in range(it):
        s = socks.socksocket(socket.AF_INET, socket.SOCK_DGRAM)
        s.set_proxy(socks.SOCKS5, ADDR, PORT)

        for j in range(count):
            payload = os.urandom(size)
            s.sendto(payload, ("test_udp", 12345))
            rsp, addr = s.recvfrom(size)
            assert rsp == payload and addr == (b"test_udp", 12345)
        s.close()


if __name__ == "__main__":
    test_tcp(1024, 1024, 10)
    test_udp(1024, 1024, 10)
