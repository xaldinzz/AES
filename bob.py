
import json
import secrets
import socket
import threading

from aes import encrypt, decrypt
from common import receive_message, send_message, start_server

HOST = "0.0.0.0"
PORT = 5001
KEYS_FILE = "keys.json"


def load_kb():
    with open(KEYS_FILE, "r", encoding="utf-8") as file:
        keys = json.load(file)

    key = bytes.fromhex(keys["Kb"])

    if len(key) != 16:
        raise ValueError("Kb harus berukuran 16 byte.")

    return key


def encrypt_json(key, data):
    plaintext = json.dumps(
        data, separators=(",", ":")
    ).encode("utf-8")

    ciphertext = encrypt(plaintext, key)

    return ciphertext.hex()


def decrypt_json(key, ciphertext_hex):
    ciphertext = bytes.fromhex(ciphertext_hex)
    plaintext = decrypt(ciphertext, key)

    return json.loads(plaintext.decode("utf-8"))


def receive_messages(sock, ks):
    while True:
        try:
            message = receive_message(sock)

            if message.get("type") == "CLOSE":
                print("\n[Bob] Alice menutup koneksi.")
                break

            if message.get("type") != "CHAT":
                print("\n[Bob] Pesan tidak dikenal:", message)
                continue

            ciphertext = message["data"]

            print("\n========== PROSES DEKRIPSI BOB ==========")
            print("[Bob] Ciphertext diterima (HEX):")
            print(ciphertext)

            data = decrypt_json(ks, ciphertext)

            print("[Bob] Plaintext hasil dekripsi:")
            print(data.get("text", ""))
            print("=========================================\n")
            print("Bob> ", end="", flush=True)

        except (ConnectionError, OSError, ValueError,
                KeyError, json.JSONDecodeError) as exc:
            print("\n[Bob] Koneksi atau dekripsi gagal:", exc)
            break


def handle_alice(conn, address, kb):
    with conn:
        try:
            print("\n[Bob] Koneksi dari:", address)

            request = receive_message(conn)

            if request.get("type") != "AUTH_START":
                send_message(conn, {
                    "type": "ERROR",
                    "message": "Permintaan autentikasi tidak valid."
                })
                return

            ticket_ciphertext = request["ticket"]

            print("\n========== PEMBUKAAN TICKET ==========")
            print("[Bob] Ticket diterima (ciphertext HEX):")
            print(ticket_ciphertext)

            ticket = decrypt_json(kb, ticket_ciphertext)

            if (ticket.get("id_a") != "Alice"
                    or ticket.get("id_b") != "Bob"):
                raise ValueError("Identitas di ticket tidak cocok.")

            ks = bytes.fromhex(ticket["ks"])
            session_id = ticket["session_id"]

            if len(ks) != 16:
                raise ValueError("Session key tidak valid.")

            print("[Bob] Ticket berhasil dibuka menggunakan Kb.")
            print("[Bob] ID Alice:", ticket["id_a"])
            print("[Bob] ID Bob:", ticket["id_b"])
            print("[Bob] Session ID:", session_id)
            print("[Bob] Session key Ks (HEX, demonstrasi):")
            print(ks.hex())
            print("======================================\n")

            n2 = secrets.randbelow(1_000_000_000) + 1

            challenge = encrypt_json(ks, {
                "session_id": session_id,
                "n2": n2
            })

            print("[Bob] Nonce tantangan N2:", n2)
            print("[Bob] Challenge terenkripsi (HEX):")
            print(challenge)

            send_message(conn, {
                "type": "CHALLENGE",
                "data": challenge
            })

            response = receive_message(conn)

            if response.get("type") != "CHALLENGE_RESPONSE":
                raise ValueError("Respons tantangan tidak valid.")

            print("\n[Bob] Respons challenge diterima (HEX):")
            print(response["data"])

            answer = decrypt_json(ks, response["data"])

            print("[Bob] Respons challenge setelah dekripsi:")
            print(answer)

            if answer.get("session_id") != session_id:
                raise ValueError("Session ID tidak cocok.")

            if answer.get("n2") != n2 - 1:
                raise ValueError("Autentikasi Alice gagal: nonce salah.")

            send_message(conn, {"type": "AUTH_OK"})

            print("\n========================================")
            print("[Bob] AUTENTIKASI ALICE BERHASIL")
            print("[Bob] Komunikasi AES dua arah aktif.")
            print("========================================")
            print("Ketik pesan untuk Alice. Gunakan /quit untuk keluar.")

            receiver = threading.Thread(
                target=receive_messages,
                args=(conn, ks),
                daemon=True
            )
            receiver.start()

            while True:
                try:
                    text = input("Bob> ")
                except (EOFError, KeyboardInterrupt):
                    break

                if text.strip() == "/quit":
                    break

                plaintext = json.dumps(
                    {"text": text},
                    separators=(",", ":")
                ).encode("utf-8")

                ciphertext = encrypt(plaintext, ks).hex()

                print("\n========== PROSES ENKRIPSI BOB ==========")
                print("[Bob] Plaintext:")
                print(text)
                print("[Bob] Data plaintext UTF-8 (HEX):")
                print(plaintext.hex())
                print("[Bob] Ciphertext AES (HEX):")
                print(ciphertext)
                print("=========================================\n")

                send_message(conn, {
                    "type": "CHAT",
                    "data": ciphertext
                })

            try:
                send_message(conn, {"type": "CLOSE"})
            except OSError:
                pass

        except (ConnectionError, OSError, ValueError,
                KeyError, json.JSONDecodeError) as exc:
            print("[Bob] Autentikasi atau komunikasi gagal:", exc)

            try:
                send_message(conn, {
                    "type": "ERROR",
                    "message": "Autentikasi gagal."
                })
            except OSError:
                pass


def main():
    kb = load_kb()
    server = start_server(HOST, PORT)

    print("Bob aktif di port", PORT)
    print("Menunggu koneksi Alice...")

    while True:
        conn, address = server.accept()

        threading.Thread(
            target=handle_alice,
            args=(conn, address, kb),
            daemon=True
        ).start()


if __name__ == "__main__":
    main()
