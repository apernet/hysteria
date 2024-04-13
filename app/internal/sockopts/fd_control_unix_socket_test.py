import socket
import array
import os
import struct
import sys


def serve(path):
    try:
        os.unlink(path)
    except OSError:
        if os.path.exists(path):
            raise

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(path)
    server.listen()
    print(f"Listening on {path}")

    try:
        while True:
            connection, client_address = server.accept()
            print(f"Client connected")

            try:
                # Receiving fd from client
                fds = array.array("i")
                msg, ancdata, flags, addr = connection.recvmsg(1, socket.CMSG_LEN(struct.calcsize('i')))
                for cmsg_level, cmsg_type, cmsg_data in ancdata:
                    if cmsg_level == socket.SOL_SOCKET and cmsg_type == socket.SCM_RIGHTS:
                        fds.frombytes(cmsg_data[:len(cmsg_data) - (len(cmsg_data) % fds.itemsize)])

                fd = fds[0]

                # We make a call to setsockopt(2) here, so client can verify we have received the fd
                # In the real scenario, the server would set things like SO_MARK,
                # we use SO_RCVBUF as it doesn't require any special capabilities.
                nbytes = struct.pack("i", 2500)
                fdsocket = fd_to_socket(fd)
                fdsocket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, nbytes)
                fdsocket.close()

                # The only protocol-like thing specified in the client implementation.
                connection.send(b'\x01')
            finally:
                connection.close()
                print("Connection closed")

    except KeyboardInterrupt:
        print("Exit")

    finally:
        server.close()
        os.unlink(path)


def fd_to_socket(fd):
    return socket.fromfd(fd, socket.AF_UNIX, socket.SOCK_STREAM)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise ValueError("unix socket path is required")

    serve(sys.argv[1])
