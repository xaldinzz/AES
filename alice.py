
import json
import secrets
import socket
import threading

from aes import encrypt, decrypt
from common import connect_to, receive_message, send_message

KDC_HOST = "192.168.184.137"
KDC_PORT = 5000

BOB_HOST = "192.168.184.136"
BOB_PORT = 5001

KEYS_FILE = "keys.json"


def load_ka():
    with open(KEYS_FILE, "r", encoding="utf-8") as file:
        keys = json.load(file)

    key = bytes.fromhex(keys["Ka"])

    if len(key) != 16:
        raise ValueError("Ka harus berukuran 16 byte.")

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


def request_ticket(ka):
    n1 = secrets.token_hex(16)

    print("\n========== PERMINTAAN SESSION KEY ==========")
    print("[Alice] Menghubungi KDC:", KDC_HOST, KDC_PORT)
    print("[Alice] ID Alice       : Alice")
    print("[Alice] ID Bob         : Bob")
    print("[Alice] Nonce N1       :", n1)

    with connect_to(KDC_HOST, KDC_PORT) as sock:
        send_message(sock, {
            "type": "TICKET_REQUEST",
            "id_a": "Alice",
            "id_b": "Bob",
            "n1": n1
        })

        response = receive_message(sock)

    if response.get("type") != "TICKET_RESPONSE":
        raise RuntimeError(f"Respons KDC tidak valid: {response}")

    print("\n[Alice] Ciphertext respons KDC:")
    print(response["encrypted"])

    package = decrypt_json(ka, response["encrypted"])

    print("\n[Alice] Respons KDC berhasil didekripsi dengan Ka.")

    if package.get("id_a") != "Alice":
        raise RuntimeError("Identitas Alice tidak cocok.")

    if package.get("id_b") != "Bob":
        raise RuntimeError("Identitas Bob tidak cocok.")

    if package.get("n1") != n1:
        raise RuntimeError("Nonce N1 tidak cocok.")

    ks = bytes.fromhex(package["ks"])

    if len(ks) != 16:
        raise RuntimeError("Session key tidak valid.")

    session_id = package["session_id"]
    ticket = package["ticket"]

    print("[Alice] Session ID:", session_id)
    print("[Alice] Session key Ks (HEX, demonstrasi):", ks.hex())
    print("[Alice] Ticket untuk Bob (ciphertext HEX):")
    print(ticket)
    print("============================================\n")

    return ks, ticket, session_id


def receive_messages(sock, ks):
    while True:
        try:
            message = receive_message(sock)

            if message.get("type") == "CLOSE":
                print("\n[Alice] Bob menutup koneksi.")
                break

            if message.get("type") != "CHAT":
                print("\n[Alice] Pesan tidak dikenal:", message)
                continue

            ciphertext = message["data"]

            print("\n========== PROSES DEKRIPSI ALICE ==========")
            print("[Alice] Ciphertext diterima (HEX):")
            print(ciphertext)

            data = decrypt_json(ks, ciphertext)

            print("[Alice] Plaintext hasil dekripsi:")
            print(data.get("text", ""))
            print("===========================================\n")
            print("Alice> ", end="", flush=True)

        except (ConnectionError, OSError, ValueError,
                KeyError, json.JSONDecodeError) as exc:
            print("\n[Alice] Koneksi atau dekripsi gagal:", exc)
            break


def main():
    ka = load_ka()

    ks, ticket, session_id = request_ticket(ka)

    print("[Alice] Menghubungi Bob:", BOB_HOST, BOB_PORT)

    with connect_to(BOB_HOST, BOB_PORT) as sock:
        send_message(sock, {
            "type": "AUTH_START",
            "ticket": ticket
        })

        challenge = receive_message(sock)

        if challenge.get("type") != "CHALLENGE":
            raise RuntimeError(
                f"Tantangan Bob tidak valid: {challenge}"
            )

        print("\n[Alice] Ciphertext challenge dari Bob:")
        print(challenge["data"])

        n2_data = decrypt_json(ks, challenge["data"])

        print("[Alice] Challenge berhasil didekripsi.")

        if n2_data.get("session_id") != session_id:
            raise RuntimeError("Session ID tantangan tidak cocok.")

        n2 = n2_data.get("n2")

        if not isinstance(n2, int) or n2 < 1:
            raise RuntimeError("Nonce N2 tidak valid.")

        answer = {
            "session_id": session_id,
            "n2": n2 - 1
        }

        encrypted_answer = encrypt_json(ks, answer)

        print("[Alice] Respons challenge terenkripsi (HEX):")
        print(encrypted_answer)

        send_message(sock, {
            "type": "CHALLENGE_RESPONSE",
            "data": encrypted_answer
        })

        result = receive_message(sock)

        if result.get("type") != "AUTH_OK":
            raise RuntimeError(
                f"Autentikasi Alice gagal: {result}"
            )

        print("\n============================================")
        print("[Alice] AUTENTIKASI BERHASIL")
        print("[Alice] Komunikasi AES dua arah aktif.")
        print("============================================")
        print("Ketik pesan untuk Bob. Gunakan /quit untuk keluar.")

        receiver = threading.Thread(
            target=receive_messages,
            args=(sock, ks),
            daemon=True
        )
        receiver.start()

        while True:
            try:
                text = input("Alice> ")
            except (EOFError, KeyboardInterrupt):
                break

            if text.strip() == "/quit":
                break

            plaintext = json.dumps(
                {"text": text},
                separators=(",", ":")
            ).encode("utf-8")

            ciphertext = encrypt(plaintext, ks).hex()

            print("\n========== PROSES ENKRIPSI ALICE ==========")
            print("[Alice] Plaintext:")
            print(text)
            print("[Alice] Data plaintext UTF-8 (HEX):")
            print(plaintext.hex())
            print("[Alice] Ciphertext AES (HEX):")
            print(ciphertext)
            print("===========================================\n")

            send_message(sock, {
                "type": "CHAT",
                "data": ciphertext
            })

        try:
            send_message(sock, {"type": "CLOSE"})
        except OSError:
            pass

    print("[Alice] Program selesai.")


if __name__ == "__main__":
    main()
