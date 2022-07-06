import socks
import socket
import time

target = "1.1.1.1"


def main():
    s = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
    s.set_proxy(socks.SOCKS5, "127.0.0.1", 1080)

    print("Sending HTTP request to %s" % target)
    start = time.time()
    s.connect((target, 80))
    s.send(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
    data = s.recv(1024)
    if not data:
        print("No data received")
    elif not data.startswith(b"HTTP/1.1 "):
        print("Invalid response received")
    else:
        print("Response received")
    end = time.time()
    s.close()

    print("Time: {} ms".format(round((end - start) * 1000, 2)))


if __name__ == "__main__":
    main()
