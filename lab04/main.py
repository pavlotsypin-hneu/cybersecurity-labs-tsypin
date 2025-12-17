import hashlib
import os

# модуль для простих обчислень
MOD = 1000007
# коефіцієнт зв’язку між ключами
K = 7

# SHA256 -> рядок
def sha256_hex(data: bytes) -> str:
    # рахуємо хеш SHA256 і повертаємо його у вигляді рядка
    return hashlib.sha256(data).hexdigest()


# Хеш файлу (зменшений по модулю)
def file_hash_mod(path: str) -> int:
    # читаємо файл у байтах
    with open(path, "rb") as f:
        data = f.read()
    # перетворюємо SHA256 у число
    return int(sha256_hex(data), 16) % MOD


# Генерація приватного ключа
def make_private_key(name: str, birth: str, secret: str) -> int:
    # об'єднуємо персональні дані
    s = (name + birth + secret).encode("utf-8")
    # приватний ключ — це хеш від цих даних
    return int(sha256_hex(s), 16) % MOD


# Генерація публічного ключа
def make_public_key(private_key: int) -> int:
    # публічний ключ пов’язаний з приватним
    return (private_key * K) % MOD


# Обернене число для K
def inv_k() -> int:
    # потрібно для відновлення приватного ключа з публічного
    return pow(K, -1, MOD)


# Створення підпису файлу
def sign_file(path: str, private_key: int) -> int:
    # рахуємо хеш документа
    h = file_hash_mod(path)
    # підпис = хеш + приватний ключ
    return (h + private_key) % MOD

# Перевірка підпису
def verify_file(path: str, signature: int, public_key: int) -> bool:
    # рахуємо хеш поточного файлу
    h = file_hash_mod(path)
    # відновлюємо приватний ключ з публічного
    private_from_public = (public_key * inv_k()) % MOD
    # очікуваний підпис
    expected = (h + private_from_public) % MOD
    # порівнюємо
    return expected == signature


# Збереження ключів у файли
def save_keys(private_key: int, public_key: int):
    with open("private_key.txt", "w", encoding="utf-8") as f:
        f.write(str(private_key))
    with open("public_key.txt", "w", encoding="utf-8") as f:
        f.write(str(public_key))


# Завантаження ключа з файлу
def load_key(path: str) -> int:
    with open(path, "r", encoding="utf-8") as f:
        return int(f.read().strip())


# Збереження підпису
def save_signature(sig_path: str, signature: int, public_key: int, target_file: str):
    # підпис, публічний ключ і назва файлу
    with open(sig_path, "w", encoding="utf-8") as f:
        f.write(f"{signature}\n")
        f.write(f"{public_key}\n")
        f.write(f"{os.path.basename(target_file)}\n")


# Завантаження підпису
def load_signature(sig_path: str):
    with open(sig_path, "r", encoding="utf-8") as f:
        lines = [x.strip() for x in f.readlines()]
    signature = int(lines[0])
    public_key = int(lines[1])
    filename = lines[2] if len(lines) > 2 else ""
    return signature, public_key, filename


# Імітація підробки файлу
def tamper_copy(src: str, dst: str):
    with open(src, "rb") as f:
        data = f.read()
    # змінюємо файл (додаємо 1 байт)
    data = data + b"\x00"
    with open(dst, "wb") as f:
        f.write(data)


# Меню програми
def menu():
    print("Спрощений цифровий підпис")
    print("1) Згенерувати ключі")
    print("2) Підписати файл")
    print("3) Перевірити підпис")
    print("4) Підробити файл і перевірити")
    print("0) Вихід")


# Головна функція
def main():
    while True:
        menu()
        choice = input("Вибір: ").strip()

        if choice == "0":
            break

        if choice == "1":
            name = input("Ім'я: ").strip()
            birth = input("Дата народження (без крапок): ").strip()
            secret = input("Секретне слово: ").strip()

            priv = make_private_key(name, birth, secret)
            pub = make_public_key(priv)
            save_keys(priv, pub)

            print("Ключі збережено")

        elif choice == "2":
            path = input("Шлях до файлу: ").strip()
            priv = load_key("private_key.txt")
            pub = load_key("public_key.txt")

            sig = sign_file(path, priv)
            sig_path = path + ".sig"
            save_signature(sig_path, sig, pub, path)

            print("Файл підписано")

        elif choice == "3":
            path = input("Шлях до файлу: ").strip()
            sig_path = input("Шлях до .sig: ").strip()

            sig, pub, _ = load_signature(sig_path)
            ok = verify_file(path, sig, pub)

            print("Підпис ДІЙСНИЙ" if ok else "Підпис ПІДРОБЛЕНИЙ")

        elif choice == "4":
            path = input("Оригінальний файл: ").strip()
            sig_path = input("Шлях до .sig: ").strip()

            fake_path = "tampered_" + os.path.basename(path)
            tamper_copy(path, fake_path)

            sig, pub, _ = load_signature(sig_path)
            ok = verify_file(fake_path, sig, pub)

            print("Підпис ДІЙСНИЙ" if ok else "Підпис ПІДРОБЛЕНИЙ")

        else:
            print("Невірний вибір")


if __name__ == "__main__":
    main()
