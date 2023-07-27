import socket
import socks
import os

ADDR = "127.0.0.1"
PORT = 11080


def test_tcp(size, count, it, domain=False):
    for i in range(it):
        s = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
        s.set_proxy(socks.SOCKS5, ADDR, PORT)

        if domain:
            s.connect(("test.tcp.com", 12345))
        else:
            s.connect(("1.2.3.4", 12345))

        for j in range(count):
            payload = os.urandom(size)
            s.send(payload)
            rsp = s.recv(size)
            assert rsp == payload

        s.close()


def test_udp(size, count, it, domain=False):
    for i in range(it):
        s = socks.socksocket(socket.AF_INET, socket.SOCK_DGRAM)
        s.set_proxy(socks.SOCKS5, ADDR, PORT)

        for j in range(count):
            payload = os.urandom(size)

            if domain:
                s.sendto(payload, ("test.udp.com", 12345))
            else:
                s.sendto(payload, ("1.2.3.4", 12345))

            rsp, addr = s.recvfrom(size)
            assert rsp == payload

            if domain:
                assert addr == (b"test.udp.com", 12345)
            else:
                assert addr == ("1.2.3.4", 12345)

        s.close()


if __name__ == "__main__":
    test_tcp(1024, 1024, 10, domain=False)
    test_tcp(1024, 1024, 10, domain=True)
    test_udp(1024, 1024, 10, domain=False)
    test_udp(1024, 1024, 10, domain=True)
    print("OK")
