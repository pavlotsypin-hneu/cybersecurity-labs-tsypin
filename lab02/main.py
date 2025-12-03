import string
import matplotlib.pyplot as plt
from collections import Counter
import time

class CaesarCipher:
    def __init__(self, shift):
        self.shift = shift
        self.alphabet_lower = 'абвгґдеєжзиіїйклмнопрстуфхцчшщьюя'
        self.alphabet_upper = 'АБВГҐДЕЄЖЗИІЇЙКЛМНОПРСТУФХЦЧШЩЬЮЯ'
        
    def encrypt(self, text):
        result = []
        for char in text:
            if char in self.alphabet_lower:
                idx = self.alphabet_lower.index(char)
                new_idx = (idx + self.shift) % len(self.alphabet_lower)
                result.append(self.alphabet_lower[new_idx])
            elif char in self.alphabet_upper:
                idx = self.alphabet_upper.index(char)
                new_idx = (idx + self.shift) % len(self.alphabet_upper)
                result.append(self.alphabet_upper[new_idx])
            else:
                result.append(char)
        return ''.join(result)
    
    def decrypt(self, text):
        result = []
        for char in text:
            if char in self.alphabet_lower:
                idx = self.alphabet_lower.index(char)
                new_idx = (idx - self.shift) % len(self.alphabet_lower)
                result.append(self.alphabet_lower[new_idx])
            elif char in self.alphabet_upper:
                idx = self.alphabet_upper.index(char)
                new_idx = (idx - self.shift) % len(self.alphabet_upper)
                result.append(self.alphabet_upper[new_idx])
            else:
                result.append(char)
        return ''.join(result)

class VigenereCipher:
    def __init__(self, key):
        self.key = key.lower()
        self.alphabet_lower = 'абвгґдеєжзиіїйклмнопрстуфхцчшщьюя'
        self.alphabet_upper = 'АБВГҐДЕЄЖЗИІЇЙКЛМНОПРСТУФХЦЧШЩЬЮЯ'
        
    def encrypt(self, text):
        result = []
        key_index = 0
        for char in text:
            if char in self.alphabet_lower:
                text_idx = self.alphabet_lower.index(char)
                key_char = self.key[key_index % len(self.key)]
                key_shift = self.alphabet_lower.index(key_char)
                new_idx = (text_idx + key_shift) % len(self.alphabet_lower)
                result.append(self.alphabet_lower[new_idx])
                key_index += 1
            elif char in self.alphabet_upper:
                text_idx = self.alphabet_upper.index(char)
                key_char = self.key[key_index % len(self.key)]
                key_shift = self.alphabet_lower.index(key_char)
                new_idx = (text_idx + key_shift) % len(self.alphabet_upper)
                result.append(self.alphabet_upper[new_idx])
                key_index += 1
            else:
                result.append(char)
        return ''.join(result)
    
    def decrypt(self, text):
        result = []
        key_index = 0
        for char in text:
            if char in self.alphabet_lower:
                text_idx = self.alphabet_lower.index(char)
                key_char = self.key[key_index % len(self.key)]
                key_shift = self.alphabet_lower.index(key_char)
                new_idx = (text_idx - key_shift) % len(self.alphabet_lower)
                result.append(self.alphabet_lower[new_idx])
                key_index += 1
            elif char in self.alphabet_upper:
                text_idx = self.alphabet_upper.index(char)
                key_char = self.key[key_index % len(self.key)]
                key_shift = self.alphabet_lower.index(key_char)
                new_idx = (text_idx - key_shift) % len(self.alphabet_upper)
                result.append(self.alphabet_upper[new_idx])
                key_index += 1
            else:
                result.append(char)
        return ''.join(result)

class CryptoAnalyzer:
    def __init__(self):
        self.alphabet = 'абвгґдеєжзиіїйклмнопрстуфхцчшщьюя'
        # Приблизна частота літер української мови
        self.ukr_freq = {
            'а': 7.2, 'о': 9.4, 'і': 6.7, 'е': 6.4, 'н': 6.7, 'т': 5.5,
            'с': 4.5, 'р': 4.7, 'в': 4.5, 'л': 3.6, 'к': 3.5, 'и': 5.3
        }
    
    def frequency_analysis(self, text):
        text_lower = text.lower()
        letters = [c for c in text_lower if c in self.alphabet]
        total = len(letters)
        if total == 0:
            return {}
        freq = Counter(letters)
        return {char: (count/total)*100 for char, count in freq.most_common()}
    
    def brute_force_caesar(self, encrypted_text):
        results = []
        for shift in range(len(self.alphabet)):
            cipher = CaesarCipher(shift)
            decrypted = cipher.decrypt(encrypted_text)
            results.append((shift, decrypted))
        return results
    
    def calculate_ic(self, text):
        """Індекс відповідності (Index of Coincidence)"""
        text_lower = ''.join([c for c in text.lower() if c in self.alphabet])
        n = len(text_lower)
        if n <= 1:
            return 0
        freq = Counter(text_lower)
        ic = sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))
        return ic

def generate_keys_from_data(birth_date, surname):
    """Генерація ключів з персональних даних"""
    # Для Цезаря: сума цифр дати народження
    caesar_shift = sum(int(d) for d in birth_date if d.isdigit())
    # Для Віженера: прізвище
    vigenere_key = surname
    return caesar_shift, vigenere_key

def compare_ciphers(text, caesar_cipher, vigenere_cipher, analyzer):
    """Порівняльний аналіз шифрів"""
    print("ПОРІВНЯЛЬНИЙ АНАЛІЗ КЛАСИЧНИХ ШИФРІВ")
    
    # Шифрування
    print(f"\nОригінальний текст:\n{text}")
    
    # Застосовуємо обидва алгоритми до одного тексту
    caesar_encrypted = caesar_cipher.encrypt(text)
    vigenere_encrypted = vigenere_cipher.encrypt(text)
    
    print(f"\nШифр Цезаря (зсув={caesar_cipher.shift}):\n{caesar_encrypted}")
    print(f"\nШифр Віженера (ключ='{vigenere_cipher.key}'):\n{vigenere_encrypted}")
    
    # Розшифрування - перевіряємо чи працює дешифрування
    caesar_decrypted = caesar_cipher.decrypt(caesar_encrypted)
    vigenere_decrypted = vigenere_cipher.decrypt(vigenere_encrypted)
    
    print(f"\nРозшифрований Цезарь:\n{caesar_decrypted}")
    print(f"\nРозшифрований Віженер:\n{vigenere_decrypted}")
    
    # Порівняльна таблиця
    print("ПОРІВНЯЛЬНА ТАБЛИЦЯ")
    print(f"{'Параметр':<30} {'Цезарь':<25} {'Віженер':<25}")
    print(f"{'Довжина шифротексту':<30} {len(caesar_encrypted):<25} {len(vigenere_encrypted):<25}")
    print(f"{'Довжина ключа':<30} {1:<25} {len(vigenere_cipher.key):<25}")
    print(f"{'Простір ключів':<30} {33:<25} {f'33^{len(vigenere_cipher.key)}':<25}")
    
    # Індекс відповідності - показує наскільки текст схожий на природну мову
    # Для української мови IC ≈ 0.06, для випадкового тексту ≈ 0.03
    caesar_ic = analyzer.calculate_ic(caesar_encrypted)
    vigenere_ic = analyzer.calculate_ic(vigenere_encrypted)
    print(f"{'Індекс відповідності':<30} {caesar_ic:.4f}{'':<20} {vigenere_ic:.4f}{'':<20}")
    
    # Дивимося які літери зустрічаються найчастіше

    print("ЧАСТОТНИЙ АНАЛІЗ")
    
    caesar_freq = analyzer.frequency_analysis(caesar_encrypted)
    vigenere_freq = analyzer.frequency_analysis(vigenere_encrypted)
    
    print("\nЦезарь - топ-5 найчастіших літер:")
    for i, (char, freq) in enumerate(list(caesar_freq.items())[:5], 1):
        print(f"  {i}. '{char}': {freq:.2f}%")
    
    print("\nВіженер - топ-5 найчастіших літер:")
    for i, (char, freq) in enumerate(list(vigenere_freq.items())[:5], 1):
        print(f"  {i}. '{char}': {freq:.2f}%")
    
    # Пробуємо зламати шифр Цезаря методом повного перебору
    print("КРИПТОАНАЛІЗ (Brute Force для Цезаря)")
    
    start_time = time.time()
    brute_results = analyzer.brute_force_caesar(caesar_encrypted)
    brute_time = time.time() - start_time
    
    print(f"\nПеребрано {len(brute_results)} варіантів за {brute_time:.4f} секунд")
    print("\nТоп-3 найімовірніших варіанти:")
    for i, (shift, text_variant) in enumerate(brute_results[:3], 1):
        print(f"\n  {i}. Зсув={shift}:")
        print(f"     {text_variant[:100]}...")
    
    # Висновки - аналізуємо стійкість до зламу
    print("ВИСНОВКИ ПРО СТІЙКІСТЬ")
    
    print("\nШифр Цезаря:")
    print("  - Дуже низька стійкість (33 можливих ключі)")
    print("  - Легко зламується brute force атакою")
    print("  - Вразливий до частотного аналізу")
    print(f"  - Індекс відповідності: {caesar_ic:.4f} (близький до відкритого тексту)")
    
    print("\nШифр Віженера:")
    print(f"  + Вища стійкість (33^{len(vigenere_cipher.key)} можливих ключів)")
    print("  + Стійкий до простого частотного аналізу")
    print("  - Вразливий до методу Касіські та аналізу IC")
    print(f"  - Індекс відповідності: {vigenere_ic:.4f} (нижчий = краще)")
    
    return {
        'caesar_freq': caesar_freq,
        'vigenere_freq': vigenere_freq,
        'caesar_ic': caesar_ic,
        'vigenere_ic': vigenere_ic
    }

def visualize_results(caesar_freq, vigenere_freq):
    # Два графіки поруч для порівняння
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))
    
    # Графік для Цезаря
    chars1 = list(caesar_freq.keys())[:10]
    freqs1 = [caesar_freq[c] for c in chars1]
    ax1.bar(chars1, freqs1, color='#3498db')
    ax1.set_title('Частотний аналіз - Шифр Цезаря', fontsize=14, fontweight='bold')
    ax1.set_xlabel('Літери')
    ax1.set_ylabel('Частота (%)')
    ax1.grid(axis='y', alpha=0.3)
    
    # Графік для Віженера
    chars2 = list(vigenere_freq.keys())[:10]
    freqs2 = [vigenere_freq[c] for c in chars2]
    ax2.bar(chars2, freqs2, color='#e74c3c')
    ax2.set_title('Частотний аналіз - Шифр Віженера', fontsize=14, fontweight='bold')
    ax2.set_xlabel('Літери')
    ax2.set_ylabel('Частота (%)')
    ax2.grid(axis='y', alpha=0.3)
    
    plt.tight_layout()
    plt.savefig('cipher_frequency_analysis.png', dpi=150, bbox_inches='tight')
    print("\nГрафіки збережено у файл: cipher_frequency_analysis.png")
    plt.show()

def main():
    # Персональні дані 
    birth_date = "20.12.2004"  # Дата народження
    surname = "Ципін"  # Прізвище
    
    # Генерація ключів
    caesar_shift, vigenere_key = generate_keys_from_data(birth_date, surname)
    
    # Ініціалізація шифрів
    caesar = CaesarCipher(caesar_shift)
    vigenere = VigenereCipher(vigenere_key)
    analyzer = CryptoAnalyzer()
    
    # Тестовий текст
    test_text = f"Захист інформації – важлива дисципліна. Так вважаю я, {surname}"
    
    # Порівняльний аналіз
    results = compare_ciphers(test_text, caesar, vigenere, analyzer)
    
    # Візуалізація
    visualize_results(results['caesar_freq'], results['vigenere_freq'])

if __name__ == "__main__":
    main()
