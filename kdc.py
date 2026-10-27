
import json
import secrets
import socket
import time

from aes import encrypt, decrypt
from common import receive_message, send_message, start_server

HOST = "0.0.0.0"
PORT = 5000
KEYS_FILE = "keys.json"


def load_keys():
    with open(KEYS_FILE, "r", encoding="utf-8") as file:
        keys = json.load(file)

    ka = bytes.fromhex(keys["Ka"])
    kb = bytes.fromhex(keys["Kb"])

    if len(ka) != 16 or len(kb) != 16:
        raise ValueError("Ka dan Kb harus masing-masing 16 byte.")

    return ka, kb


def encrypt_json(key, data):
    plaintext = json.dumps(data, separators=(",", ":")).encode("utf-8")
    return encrypt(plaintext, key).hex()


def decrypt_json(key, ciphertext_hex):
    plaintext = decrypt(bytes.fromhex(ciphertext_hex), key)
    return json.loads(plaintext.decode("utf-8"))


def main():
    ka, kb = load_keys()
    server = start_server(HOST, PORT)

    print("KDC aktif di port", PORT)
    print("Menunggu permintaan dari Alice...")

    while True:
        conn, address = server.accept()

        with conn:
            try:
                request = receive_message(conn)

                if request.get("type") != "TICKET_REQUEST":
                    send_message(conn, {
                        "type": "ERROR",
                        "message": "Jenis permintaan tidak dikenal."
                    })
                    continue

                id_a = request.get("id_a")
                id_b = request.get("id_b")
                n1 = request.get("n1")

                if id_a != "Alice" or id_b != "Bob":
                    send_message(conn, {
                        "type": "ERROR",
                        "message": "Identitas tidak valid."
                    })
                    continue

                if not isinstance(n1, str) or not (1 <= len(n1) <= 128):
                    send_message(conn, {
                        "type": "ERROR",
                        "message": "Nonce tidak valid."
                    })
                    continue

                # KDC membuat session key AES-128 acak.
                ks = secrets.token_bytes(16)
                session_id = secrets.token_hex(8)

                # Ticket ini hanya dapat dibuka oleh Bob menggunakan Kb.
                ticket_for_bob = encrypt_json(kb, {
                    "id_a": id_a,
                    "id_b": id_b,
                    "ks": ks.hex(),
                    "session_id": session_id
                })

                # Respons ini hanya dapat dibuka Alice menggunakan Ka.
                response_for_alice = encrypt_json(ka, {
                    "id_a": id_a,
                    "id_b": id_b,
                    "n1": n1,
                    "ks": ks.hex(),
                    "session_id": session_id,
                    "ticket": ticket_for_bob
                })

                send_message(conn, {
                    "type": "TICKET_RESPONSE",
                    "encrypted": response_for_alice
                })

                print(f"[KDC] Ticket dibuat untuk {id_a} dan {id_b}.")
                print("[KDC] Session key dibuat dan didistribusikan secara terenkripsi.")

            except (ConnectionError, ValueError, KeyError, json.JSONDecodeError) as exc:
                print("[KDC] Permintaan gagal:", exc)
                try:
                    send_message(conn, {
                        "type": "ERROR",
                        "message": "Permintaan tidak dapat diproses."
                    })
                except OSError:
                    pass


if __name__ == "__main__":
    main()
