import hashlib
import base64


# Ключ з персональних даних
def make_key(personal: str) -> bytes:
    # робимо 32 байти ключа з рядка (SHA-256)
    return hashlib.sha256(personal.encode("utf-8")).digest()

# Генерація псевдо-ключового потоку для XOR
def keystream(key: bytes, n: int) -> bytes:
    # добираємо байти потоком через хеші
    out = b""
    counter = 0
    while len(out) < n:
        block = hashlib.sha256(key + counter.to_bytes(4, "big")).digest()
        out += block
        counter += 1
    return out[:n]

# Шифрування (XOR + Base64)
def encrypt_text(plain: str, key: bytes) -> str:
    data = plain.encode("utf-8")
    ks = keystream(key, len(data))
    cipher = bytes([a ^ b for a, b in zip(data, ks)])
    # щоб було зручно пересилати в листі
    return base64.b64encode(cipher).decode("utf-8")


# Розшифрування (Base64 + XOR)
def decrypt_text(cipher_b64: str, key: bytes) -> str:
    cipher = base64.b64decode(cipher_b64.encode("utf-8"))
    ks = keystream(key, len(cipher))
    plain = bytes([a ^ b for a, b in zip(cipher, ks)])
    return plain.decode("utf-8", errors="replace")


# Меню
def menu():
    print("\nEmail-шифратор")
    print("1) Згенерувати ключ з персональних даних")
    print("2) Зашифрувати повідомлення")
    print("3) Розшифрувати повідомлення")
    print("4) Демонстрація обміну")
    print("0) Вихід")


def main():
    key = None

    while True:
        menu()
        choice = input("Вибір: ").strip()

        if choice == "0":
            break

        if choice == "1":
            personal = input("Введи персональні дані (напр. Email+ПІБ+дата): ").strip()
            key = make_key(personal)
            print("Ключ готовий (32 байти).")

        elif choice == "2":
            if key is None:
                print("Спочатку згенеруй ключ (пункт 1).")
                continue
            msg = input("Текст повідомлення: ")
            enc = encrypt_text(msg, key)
            print("\nЗашифроване (Base64):")
            print(enc)

        elif choice == "3":
            if key is None:
                print("Спочатку згенеруй ключ (пункт 1).")
                continue
            enc = input("Встав зашифроване (Base64): ").strip()
            dec = decrypt_text(enc, key)
            print("\nРозшифроване повідомлення:")
            print(dec)

        elif choice == "4":
            print("\nДемо обміну: Євген -> Павло")
            print("Умовно: вони домовились про спільний секрет/рядок для ключа.")
            personal = "pavlo.tsypin@example.com|ПавлоЦипін20122004|Ципін"
            key_demo = make_key(personal)

            msg = "Павло, ти вже зробив лабу з ЗІ? Можеш скинути код, я звірю зі своїм."
            enc = encrypt_text(msg, key_demo)

            print("\nЄвген відправляє зашифрований текст:")
            print(enc)

            dec = decrypt_text(enc, key_demo)
            print("\nПавло розшифровує і читає:")
            print(dec)

            # показуємо, що неправильний ключ дає не те
            wrong_key = make_key("інший_рядок_для_ключа")
            wrong_dec = decrypt_text(enc, wrong_key)
            print("\nЯкщо ключ неправильний, виходить не те:")
            print(wrong_dec)

        else:
            print("Невірний вибір.")


if __name__ == "__main__":
    main()
