import socket
import socks
import time

TARGET = "1.1.1.1"


def test_tcp() -> None:
    s = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
    s.set_proxy(socks.SOCKS5, "127.0.0.1", 1080)

    print(f"TCP - Sending HTTP request to {TARGET}")
    start = time.time()
    s.connect((TARGET, 80))
    s.send(b"GET / HTTP/1.1\r\nHost: " + TARGET.encode() + b"\r\n\r\n")
    data = s.recv(1024)
    if not data:
        print("No data received")
    elif not data.startswith(b"HTTP/1.1 "):
        print("Invalid response received")
    else:
        print("TCP test passed")
    end = time.time()
    s.close()

    print(f"Time: {round((end - start) * 1000, 2)} ms")


def test_udp() -> None:
    s = socks.socksocket(socket.AF_INET, socket.SOCK_DGRAM)
    s.set_proxy(socks.SOCKS5, "127.0.0.1", 1080)

    req = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05\x62\x61\x69\x64\x75\x03\x63\x6f\x6d\x00\x00\x01\x00\x01"
    print(f"UDP - Sending DNS request to {TARGET}")
    start = time.time()
    s.sendto(req, (TARGET, 53))
    (rsp, address) = s.recvfrom(4096)
    if address[0] == TARGET and address[1] == 53 and rsp[0] == req[0] and rsp[1] == req[1]:
        print("UDP test passed")
    else:
        print("Invalid response received")
    end = time.time()
    s.close()

    print(f"Time: {round((end - start) * 1000, 2)} ms")


if __name__ == "__main__":
    test_tcp()
    test_udp()
