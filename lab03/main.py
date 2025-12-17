from PIL import Image
import numpy as np
import os

END_MARK = "<<<END>>>"

# -------------------------------------------------
# Текст -> біти
# -------------------------------------------------
def text_to_bits(text: str) -> list:
    bits = []
    for char in text:
        b = format(ord(char), "08b")
        bits.extend([int(x) for x in b])
    return bits


# -------------------------------------------------
# Біти -> текст
# -------------------------------------------------
def bits_to_text(bits: list) -> str:
    chars = []
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        chars.append(chr(int("".join(map(str, byte)), 2)))
    return "".join(chars)


# -------------------------------------------------
# Приховування повідомлення
# -------------------------------------------------
def hide_message(input_image: str, output_image: str, message: str):
    img = Image.open(input_image).convert("RGB")
    pixels = np.array(img)

    message += END_MARK
    bits = text_to_bits(message)

    h, w, _ = pixels.shape
    max_bits = h * w * 3

    if len(bits) > max_bits:
        raise ValueError("Повідомлення занадто довге")

    idx = 0
    for y in range(h):
        for x in range(w):
            for c in range(3):
                if idx < len(bits):
                    pixels[y, x, c] = (pixels[y, x, c] & 254) | bits[idx]
                    idx += 1

    Image.fromarray(pixels).save(output_image)
    print("Повідомлення приховано у файл:", output_image)


# -------------------------------------------------
# Витяг повідомлення
# -------------------------------------------------
def extract_message(image_path: str) -> str:
    img = Image.open(image_path).convert("RGB")
    pixels = np.array(img)

    bits = []
    for y in range(pixels.shape[0]):
        for x in range(pixels.shape[1]):
            for c in range(3):
                bits.append(pixels[y, x, c] & 1)

    text = bits_to_text(bits)
    end = text.find(END_MARK)

    if end != -1:
        return text[:end]
    else:
        return "Повідомлення не знайдено"


# -------------------------------------------------
# Аналіз змін зображення
# -------------------------------------------------
def analyze_changes(original: str, modified: str):
    img1 = np.array(Image.open(original).convert("RGB"))
    img2 = np.array(Image.open(modified).convert("RGB"))

    diff = img1 != img2
    total = img1.size
    changed = diff.sum()

    percent = (changed / total) * 100
    print(f"Змінено пікселів: {changed} з {total}")
    print(f"Відсоток змін: {percent:.4f}%")


# -------------------------------------------------
# Демонстрація роботи
# -------------------------------------------------
if __name__ == "__main__":
    print("LSB-стеганографія")
    print("------------------")

    print("Алгоритм:")
    print("1. Текст переводиться у біти")
    print("2. Біти записуються у молодші біти RGB")
    print("3. Зображення візуально не змінюється\n")

    original_image = "original.png"
    steganography_image = "steganography.png"

    secret_text = "Tsypin Pavlo 20.12.2004"

    hide_message(original_image, steganography_image, secret_text)

    extracted = extract_message(steganography_image)
    print("Витягнуте повідомлення:", extracted)

    analyze_changes(original_image, steganography_image)
