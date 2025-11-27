import re
from datetime import datetime

# Невеликий словник для перевірки
COMMON_WORDS = {
    'password', 'qwerty', 'admin', 'user', 'login', 'welcome',
    'trust', 'secret', 'hello', 'iloveyou', 'dragon', 'letmein',
    'ivan', 'oleg', 'olena', 'maria', 'andriy', 'pavlo'
}


def normalize(text: str) -> str:
    """Привести до нижнього регістру для пошуку"""
    return (text or '').lower()


def parse_pib(pib: str) -> dict:
    """
    Розпарсити ПІБ (прізвище, ім'я, по-батькові).
    """
    parts = [p for p in (pib or '').strip().split() if p]
    surname = name = patronymic = None
    if len(parts) >= 1:
        surname = parts[0]
    if len(parts) >= 2:
        name = parts[1]
    if len(parts) >= 3:
        patronymic = ' '.join(parts[2:])  # на випадок подвійного по-батькові
    return {'surname': surname, 'name': name, 'patronymic': patronymic}


def personal_overlap(password: str, personal: dict) -> dict:
    """Аналіз зв'язку пароля з персональними даними"""
    p = normalize(password)
    hits = []

    # Ім'я / прізвище / по-батькові
    for key in ('name', 'surname', 'patronymic'):
        value = personal.get(key)
        if value:
            v = normalize(value)
            if v and v in p:
                hits.append((key, value))

    # Різні варіанти дати
    bdate = personal.get('birthdate')
    if bdate:
        for fmt in ('%d.%m.%Y', '%d-%m-%Y', '%Y-%m-%d'):
            try:
                dt = datetime.strptime(bdate, fmt)
                break
            except Exception:
                dt = None
        if dt:
            year = str(dt.year)
            month = f"{dt.month:02d}"
            day = f"{dt.day:02d}"
            # перевірки: рік, дві останні цифри року, день+місяць, різні формати
            variants = {year, year[-2:], day + month, month + day, day + '.' + month, day + month + year}
            for var in variants:
                if var and var in p:
                    hits.append(('birthdate_fragment', var))

    return {'count': len(hits), 'hits': hits}


def dictionary_check(password: str) -> list:
    """Перевірка наявності словникових слів як підрядка"""
    p = normalize(password)
    found = []
    for w in COMMON_WORDS:
        if w in p:
            found.append(w)
    return found


def complexity_score(password: str, personal: dict) -> dict:
    """Оцінка складності та остаточний бал 1..10."""
    length = len(password or '')

    # Довжина
    if length >= 16:
        length_points = 4
    elif length >= 12:
        length_points = 3
    elif length >= 9:
        length_points = 2
    elif length >= 8:
        length_points = 1
    else:
        length_points = 0

    # Різноманітність
    has_lower = bool(re.search(r'[a-zа-яёіїєґ]', password, re.IGNORECASE))
    has_upper = bool(re.search(r'[A-ZА-ЯЁІЇЄҐ]', password))
    has_digit = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[^\w]', password))
    variety = sum([has_lower, has_upper, has_digit, has_special])
    variety_points = min(4, variety)  # 0..4

    # Базовий бал 0..8
    base = length_points + variety_points

    # Штрафи
    dict_found = dictionary_check(password)
    personal = personal_overlap(password, personal)

    penalty = 0
    if dict_found:
        penalty += len(dict_found) * 1  # кожне словникове слово -1
    if personal['count'] > 0:
        penalty += personal['count'] * 2  # персональні збіги сильніший штраф

    # Перевести в шкалу 1..10
    raw = base - penalty
    raw = max(0, min(8, raw))
    score = 1 + round((raw / 8) * 9)

    info = {
        'length': length,
        'length_points': length_points,
        'has_lower': has_lower,
        'has_upper': has_upper,
        'has_digit': has_digit,
        'has_special': has_special,
        'variety_points': variety_points,
        'dictionary_words': dict_found,
        'personal_hits': personal,
        'raw_points': raw,
        'score_1_10': score
    }
    return info


def recommendations(password: str, analysis: dict) -> list:
    """Генерація конкретних рекомендацій для покращення безпеки."""
    recs = []
    # Уникайте персональних даних
    if analysis['personal_hits']['count'] > 0:
        recs.append('Уникайте вбудовування імен, прізвищ або дат народження у пароль.')

    # Словникові слова
    if analysis['dictionary_words']:
        recs.append('Не використовуйте звичні слова або фрази зі словника (наприклад: {}).'.format(', '.join(analysis['dictionary_words'])))

    # Довжина
    if analysis['length'] < 12:
        recs.append('Збільшіть довжину пароля: рекомендується щонайменше 12-16 символів.')

    # Різноманітність
    if not analysis['has_upper']:
        recs.append('Додайте великі літери (A-Z).')
    if not analysis['has_lower']:
        recs.append('Додайте малі літери (a-z).')
    if not analysis['has_digit']:
        recs.append('Додайте цифри.')
    if not analysis['has_special']:
        recs.append("""Додайте спеціальні символи: !@#$%^&*()_+-=[]{};:'",.<>/?""")

    recs.append('Використовуйте довгу випадкову фразу (passphrase) або менеджер паролів; комбінуйте слова, цифри та символи.')

    return recs


def analyze(password: str, personal: dict) -> dict:
    """Виконати повний аналіз та повернути звіт."""
    comp = complexity_score(password, personal)
    recs = recommendations(password, comp)

    report = {
        'password': password,
        'score': comp['score_1_10'],
        'details': comp,
        'recommendations': recs
    }
    return report


def input_with_default(prompt: str, default: str = '') -> str:
    """Введення з підказкою та можливістю залишити пусто."""
    txt = input(prompt).strip()
    if txt == '' and default != '':
        return default
    return txt


if __name__ == '__main__':
    print("Аналізатор безпеки пароля — введіть дані для тесту.")
    print("Увага: не вводьте чужі персональні дані без їхньої явної згоди.\n")

    passwd = input_with_default("Введіть пароль для аналізу: ")
    pib = input_with_default("Введіть ПІБ (Прізвище Ім'я По-батькові) — через пробіл: ")
    birth = input_with_default("Введіть дату народження (DD.MM.YYYY або DD-MM-YYYY або YYYY-MM-DD): ")

    parsed = parse_pib(pib)
    personal = {
        'name': parsed['name'],
        'surname': parsed['surname'],
        'birthdate': birth
    }

    report = analyze(passwd, personal)

    print("\n=== Звіт аналізу пароля ===")
    print(f"Пароль: {report['password']}")
    print(f"Оцінка (1-10): {report['score']}")
    print("\nДеталі:")
    d = report['details']
    print(f" - Довжина: {d['length']} (бал: {d['length_points']})")
    print(f" - Різноманітність: великі={d['has_upper']}, малі={d['has_lower']}, цифри={d['has_digit']}, спец={d['has_special']} (бал: {d['variety_points']})")
    if d['dictionary_words']:
        print(f" - Знайдені словникові слова: {', '.join(d['dictionary_words'])}")
    if d['personal_hits']['count'] > 0:
        hits = '; '.join([f"{k}:{v}" for k, v in d['personal_hits']['hits']])
        print(f" - Персональні збіги: {hits}")

    print("\nРекомендації:")
    for r in report['recommendations']:
        print(" -", r)
