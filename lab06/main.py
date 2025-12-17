import sqlite3
from datetime import datetime


DB_NAME = "demo_sqli.db"
LOG_NAME = "attacks.log"


def log_event(text: str):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_NAME, "a", encoding="utf-8") as f:
        f.write(f"[{ts}] {text}\n")


def init_db():
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()

    cur.execute("DROP TABLE IF EXISTS users")
    cur.execute("DROP TABLE IF EXISTS students")

    cur.execute("""
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL
    )
    """)

    cur.execute("""
    CREATE TABLE students (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        full_name TEXT NOT NULL,
        group_name TEXT NOT NULL,
        phone TEXT NOT NULL
    )
    """)

    cur.executemany(
        "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
        [
            ("admin", "hneu2022", "administrator"),
            ("pavlo", "20122004", "student"),
            ("yevhen", "qwerty", "student"),
        ]
    )

    cur.executemany(
        "INSERT INTO students (full_name, group_name, phone) VALUES (?, ?, ?)",
        [
            ("Ципін Павло", "ІПЗ-21", "+380991112233"),
            ("Гур`єв Євген", "ІПЗ-21", "+380631114455"),
            ("Халіна Ольга", "ІПЗ-22", "+380661119900"),
            ("Ячунскас Вітас", "ІПЗ-21", "+380982130011"),
        ]
    )

    conn.commit()
    conn.close()


# -------------------- ВРАЗЛИВІ ФУНКЦІЇ --------------------

def login_vulnerable(conn: sqlite3.Connection, username: str, password: str):
    cur = conn.cursor()
    query = (
        "SELECT id, username, role FROM users "
        f"WHERE username = '{username}' AND password = '{password}'"
    )
    log_event(f"[VULN LOGIN] query={query}")
    return cur.execute(query).fetchone()


def search_students_vulnerable(conn: sqlite3.Connection, name_part: str):
    cur = conn.cursor()
    query = (
        "SELECT id, full_name, group_name, phone FROM students "
        f"WHERE full_name LIKE '%{name_part}%'"
    )
    log_event(f"[VULN SEARCH] query={query}")
    return cur.execute(query).fetchall()


# -------------------- ЗАХИЩЕНІ ФУНКЦІЇ --------------------

def login_safe(conn: sqlite3.Connection, username: str, password: str):
    cur = conn.cursor()
    query = "SELECT id, username, role FROM users WHERE username = ? AND password = ?"
    log_event(f"[SAFE LOGIN] username={username!r}")
    return cur.execute(query, (username, password)).fetchone()


def search_students_safe(conn: sqlite3.Connection, name_part: str):
    cur = conn.cursor()
    query = "SELECT id, full_name, group_name, phone FROM students WHERE full_name LIKE ?"
    log_event(f"[SAFE SEARCH] name_part={name_part!r}")
    return cur.execute(query, (f"%{name_part}%",)).fetchall()


# -------------------- ДЕМО АТАКИ --------------------

def demo_attack(conn: sqlite3.Connection):
    print("\nДЕМО: SQL-інʼєкція на вразливій авторизації")
    print("Приклад payload для username:")
    print("  admin'--")
    print("Пароль можна вводити будь-який.\n")

    u = "admin'--"
    p = "anything"

    res_v = login_vulnerable(conn, u, p)
    res_s = login_safe(conn, u, p)

    print("Результат VULNERABLE:", "УСПІХ (увійшов)" if res_v else "НЕВДАЧА")
    print("Результат SAFE:", "УСПІХ (увійшов)" if res_s else "НЕВДАЧА")

    print("\nДЕМО: витік даних через вразливий пошук")
    print("Приклад payload для пошуку:")
    print("  ' OR 1=1--\n")

    q = "' OR 1=1--"
    rows_v = search_students_vulnerable(conn, q)
    rows_s = search_students_safe(conn, q)

    print(f"VULNERABLE повернув записів: {len(rows_v)}")
    print(f"SAFE повернув записів: {len(rows_s)}")


# -------------------- ІНТЕРФЕЙС --------------------

def print_students(rows):
    if not rows:
        print("Нічого не знайдено.")
        return
    for r in rows:
        print(f"#{r[0]} | {r[1]} | {r[2]} | {r[3]}")


def menu():
    print("\n=== Демонстрація SQL-інʼєкції ===")
    print("1) Ініціалізувати БД (створити заново)")
    print("2) Вразлива авторизація")
    print("3) Захищена авторизація")
    print("4) Вразливий пошук студентів")
    print("5) Захищений пошук студентів")
    print("6) Автодемо атаки (vuln vs safe)")
    print("0) Вихід")


def main():
    if not (os.path.exists(DB_NAME)):
        init_db()

    conn = sqlite3.connect(DB_NAME)

    while True:
        menu()
        choice = input("Вибір: ").strip()

        if choice == "0":
            break

        if choice == "1":
            init_db()
            print("БД створено заново.")

        elif choice == "2":
            u = input("Username: ")
            p = input("Password: ")
            try:
                res = login_vulnerable(conn, u, p)
                print("Успішний вхід:", res) if res else print("Вхід не виконано.")
            except Exception as e:
                log_event(f"[VULN LOGIN ERROR] {e}")
                print("Помилка (vulnerable):", e)

        elif choice == "3":
            u = input("Username: ")
            p = input("Password: ")
            try:
                res = login_safe(conn, u, p)
                print("Успішний вхід:", res) if res else print("Вхід не виконано.")
            except Exception as e:
                log_event(f"[SAFE LOGIN ERROR] {e}")
                print("Помилка (safe):", e)

        elif choice == "4":
            q = input("Пошук ПІБ (частина): ")
            try:
                rows = search_students_vulnerable(conn, q)
                print_students(rows)
            except Exception as e:
                log_event(f"[VULN SEARCH ERROR] {e}")
                print("Помилка (vulnerable):", e)

        elif choice == "5":
            q = input("Пошук ПІБ (частина): ")
            try:
                rows = search_students_safe(conn, q)
                print_students(rows)
            except Exception as e:
                log_event(f"[SAFE SEARCH ERROR] {e}")
                print("Помилка (safe):", e)

        elif choice == "6":
            demo_attack(conn)

        else:
            print("Невірний вибір.")

    conn.close()


if __name__ == "__main__":
    import os
    main()
