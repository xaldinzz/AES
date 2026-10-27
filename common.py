
import json
import socket
import struct


def send_message(sock, message):
    """Kirim pesan JSON dengan header panjang 4 byte."""
    data = json.dumps(message).encode("utf-8")
    header = struct.pack("!I", len(data))
    sock.sendall(header + data)


def receive_exact(sock, size):
    """Terima tepat sejumlah byte yang diminta."""
    result = bytearray()

    while len(result) < size:
        chunk = sock.recv(size - len(result))

        if not chunk:
            raise ConnectionError("Koneksi terputus.")

        result.extend(chunk)

    return bytes(result)


def receive_message(sock):
    """Terima satu pesan JSON."""
    header = receive_exact(sock, 4)
    length = struct.unpack("!I", header)[0]

    if length > 1_000_000:
        raise ValueError("Pesan terlalu besar.")

    data = receive_exact(sock, length)
    return json.loads(data.decode("utf-8"))


def connect_to(host, port):
    """Membuka koneksi TCP ke host tujuan."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    return sock


def start_server(host, port):
    """Membuat server TCP dan menunggu koneksi."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(5)

    print(f"Server berjalan pada {host}:{port}")
    return server
