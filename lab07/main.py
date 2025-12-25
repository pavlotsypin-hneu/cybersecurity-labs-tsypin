import os
import time
import hashlib
from datetime import datetime
from typing import Tuple, Dict
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from PIL import Image
import numpy as np
import matplotlib.pyplot as plt
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext


class SecurityAnalytics:
    def __init__(self):
        self.metrics = {'operations': [], 'encryption': {}, 'steganography': {}, 'total': {}}
    
    def record_operation(self, operation: str, duration: float, input_size: int, 
                        output_size: int, details: Dict = None):
        record = {
            'operation': operation,
            'duration': duration,
            'input_size': input_size,
            'output_size': output_size,
            'ratio': output_size / input_size if input_size > 0 else 0,
            'details': details or {}
        }
        self.metrics['operations'].append(record)
        
        if 'encrypt' in operation.lower():
            self.metrics['encryption'] = record
        elif 'steg' in operation.lower():
            self.metrics['steganography'] = record
    
    def generate_report(self) -> str:
        ops = self.metrics['operations']
        if not ops:
            return "Немає даних для звіту"
        
        total_time = sum(op['duration'] for op in ops)
        original_size = ops[0]['input_size']
        final_size = ops[-1]['output_size']
        
        report = "=" * 60 + "\n"
        report += "ЗВІТ ПРО ЕФЕКТИВНІСТЬ СИСТЕМИ ЗАХИСТУ\n"
        report += "=" * 60 + "\n\n"
        
        report += f"Загальний час: {total_time:.4f} с\n"
        report += f"Оригінальний розмір: {self._fmt(original_size)}\n"
        report += f"Фінальний розмір: {self._fmt(final_size)}\n"
        report += f"Накладні витрати: {self._fmt(final_size - original_size)}\n\n"
        
        if self.metrics['encryption']:
            enc = self.metrics['encryption']
            report += "ЕТАП 1: ШИФРУВАННЯ AES-256\n"
            report += f"Час: {enc['duration']:.4f} с\n"
            report += f"Розмір: {self._fmt(enc['input_size'])} -> {self._fmt(enc['output_size'])}\n\n"
        
        if self.metrics['steganography']:
            steg = self.metrics['steganography']
            report += "ЕТАП 2: СТЕГАНОГРАФІЯ LSB\n"
            report += f"Час: {steg['duration']:.4f} с\n"
            report += f"Розмір контейнера: {self._fmt(steg['output_size'])}\n"
            if 'usage_percent' in steg['details']:
                report += f"Використання: {steg['details']['usage_percent']:.1f}%\n"
        
        report += "\n" + "=" * 60 + "\n"
        return report
    
    def _fmt(self, size: int) -> str:
        for unit in ['Б', 'КБ', 'МБ']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} ГБ"
    
    def plot_metrics(self, save_path: str = None):
        if not self.metrics['operations']:
            return
        
        fig, axes = plt.subplots(2, 2, figsize=(10, 8))
        fig.suptitle('Аналіз системи захисту', fontsize=14)
        
        ops_names = [op['operation'] for op in self.metrics['operations']]
        durations = [op['duration'] for op in self.metrics['operations']]
        
        axes[0, 0].bar(ops_names, durations, color=['#2ecc71', '#3498db', '#e74c3c', '#f39c12'])
        axes[0, 0].set_ylabel('Час (с)')
        axes[0, 0].set_title('Час виконання')
        axes[0, 0].tick_params(axis='x', rotation=45)
        
        input_sizes = [op['input_size'] for op in self.metrics['operations']]
        output_sizes = [op['output_size'] for op in self.metrics['operations']]
        x = np.arange(len(ops_names))
        
        axes[0, 1].bar(x - 0.2, input_sizes, 0.4, label='Вхід', color='#3498db')
        axes[0, 1].bar(x + 0.2, output_sizes, 0.4, label='Вихід', color='#2ecc71')
        axes[0, 1].set_ylabel('Байти')
        axes[0, 1].set_title('Розміри файлів')
        axes[0, 1].legend()
        
        ratios = [op['ratio'] for op in self.metrics['operations']]
        axes[1, 0].bar(ops_names, ratios, color=['#2ecc71' if r <= 1 else '#e74c3c' for r in ratios])
        axes[1, 0].axhline(y=1, color='black', linestyle='--')
        axes[1, 0].set_ylabel('Коефіцієнт')
        axes[1, 0].set_title('Зміна розміру')
        
        if self.metrics['encryption']:
            sizes = [
                self.metrics['operations'][0]['input_size'],
                self.metrics['encryption']['output_size'],
                self.metrics['operations'][-1]['output_size']
            ]
            axes[1, 1].plot(['Оригінал', 'Після AES', 'Фінал'], sizes, 
                           marker='o', linewidth=2, color='#9b59b6')
            axes[1, 1].set_ylabel('Байти')
            axes[1, 1].set_title('Зростання розміру')
        
        plt.tight_layout()
        if save_path:
            plt.savefig(save_path, dpi=150)
        return fig


class AESEncryption:
    @staticmethod
    def generate_key(password: str, salt: bytes = None) -> Tuple[bytes, bytes]:
        if salt is None:
            salt = get_random_bytes(32)
        key = PBKDF2(password, salt, dkLen=32, count=100000)
        return key, salt
    
    @staticmethod
    def encrypt(data: bytes, password: str) -> bytes:
        key, salt = AESEncryption.generate_key(password)
        cipher = AES.new(key, AES.MODE_CBC)
        padding = 16 - (len(data) % 16)
        padded = data + bytes([padding] * padding)
        encrypted = cipher.encrypt(padded)
        return salt + cipher.iv + encrypted
    
    @staticmethod
    def decrypt(encrypted: bytes, password: str) -> bytes:
        salt = encrypted[:32]
        iv = encrypted[32:48]
        ciphertext = encrypted[48:]
        key, _ = AESEncryption.generate_key(password, salt)
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        decrypted = cipher.decrypt(ciphertext)
        padding = decrypted[-1]
        return decrypted[:-padding]


class LSBSteganography:
    @staticmethod
    def embed(image_path: str, data: bytes, output_path: str) -> Dict:
        img = Image.open(image_path)
        arr = np.array(img)
        
        header = len(data).to_bytes(4, byteorder='big')
        full_data = header + data
        bits = ''.join([format(byte, '08b') for byte in full_data])
        
        capacity = (arr.shape[0] * arr.shape[1] * 3) // 8
        if len(full_data) > capacity:
            raise ValueError(f"Дані завеликі! Максимум: {capacity} байт")
        
        idx = 0
        for i in range(arr.shape[0]):
            for j in range(arr.shape[1]):
                for k in range(3):
                    if idx < len(bits):
                        arr[i, j, k] = (arr[i, j, k] & 0xFE) | int(bits[idx])
                        idx += 1
        
        Image.fromarray(arr).save(output_path, 'PNG')
        return {'capacity': capacity, 'usage_percent': (len(full_data) / capacity) * 100}
    
    @staticmethod
    def extract(image_path: str) -> bytes:
        arr = np.array(Image.open(image_path))
        bits = [arr[i, j, k] & 1 for i in range(arr.shape[0]) 
                for j in range(arr.shape[1]) for k in range(3)]
        
        header_bytes = bytes([int(''.join(map(str, bits[i:i+8])), 2) for i in range(0, 32, 8)])
        length = int.from_bytes(header_bytes, byteorder='big')
        
        total_bits = (length + 4) * 8
        data_bits = bits[32:total_bits]
        return bytes([int(''.join(map(str, data_bits[i:i+8])), 2) 
                     for i in range(0, len(data_bits), 8)])


class IntegratedSecuritySystem:
    def __init__(self):
        self.analytics = SecurityAnalytics()
        self.aes = AESEncryption()
        self.steg = LSBSteganography()
    
    def protect_file(self, input_file: str, container: str, password: str, output: str) -> Dict:
        with open(input_file, 'rb') as f:
            data = f.read()
        
        start = time.time()
        encrypted = self.aes.encrypt(data, password)
        enc_time = time.time() - start
        self.analytics.record_operation('Шифрування AES', enc_time, len(data), len(encrypted))
        
        start = time.time()
        details = self.steg.embed(container, encrypted, output)
        steg_time = time.time() - start
        self.analytics.record_operation('Стеганографія LSB', steg_time, 
                                       len(encrypted), os.path.getsize(output), details)
        
        return {'success': True, 'hash': hashlib.sha256(data).hexdigest()}
    
    def recover_file(self, protected: str, password: str, output: str) -> Dict:
        start = time.time()
        encrypted = self.steg.extract(protected)
        ext_time = time.time() - start
        self.analytics.record_operation('Витягування LSB', ext_time, 
                                       os.path.getsize(protected), len(encrypted))
        
        start = time.time()
        try:
            decrypted = self.aes.decrypt(encrypted, password)
            dec_time = time.time() - start
            self.analytics.record_operation('Дешифрування AES', dec_time, 
                                           len(encrypted), len(decrypted))
            
            with open(output, 'wb') as f:
                f.write(decrypted)
            
            return {'success': True, 'hash': hashlib.sha256(decrypted).hexdigest()}
        except:
            return {'success': False, 'error': 'Неправильний пароль'}


class SecuritySystemGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Система захисту")
        self.root.geometry("800x600")
        self.system = IntegratedSecuritySystem()
        self.input_file = None
        self.container = None
        self.protected = None
        self.create_widgets()
    
    def create_widgets(self):
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        protect_frame = ttk.Frame(notebook)
        notebook.add(protect_frame, text="Захист")
        
        ttk.Label(protect_frame, text="Файл:").pack(anchor='w', padx=5, pady=(10,0))
        file_frame = ttk.Frame(protect_frame)
        file_frame.pack(fill='x', padx=5, pady=5)
        self.file_label = tk.Label(file_frame, text="Не обрано", fg="gray")
        self.file_label.pack(side='left')
        ttk.Button(file_frame, text="Обрати", command=self.select_input).pack(side='right')
        
        ttk.Label(protect_frame, text="Контейнер:").pack(anchor='w', padx=5)
        cont_frame = ttk.Frame(protect_frame)
        cont_frame.pack(fill='x', padx=5, pady=5)
        self.cont_label = tk.Label(cont_frame, text="Не обрано", fg="gray")
        self.cont_label.pack(side='left')
        ttk.Button(cont_frame, text="Обрати PNG", command=self.select_container).pack(side='right')
        
        ttk.Label(protect_frame, text="Пароль:").pack(anchor='w', padx=5)
        self.pass_entry = ttk.Entry(protect_frame, show="*")
        self.pass_entry.pack(fill='x', padx=5, pady=5)
        
        ttk.Button(protect_frame, text="Захистити файл", 
                  command=self.protect).pack(pady=10)
        
        self.protect_log = scrolledtext.ScrolledText(protect_frame, height=12)
        self.protect_log.pack(fill='both', expand=True, padx=5, pady=5)
        
        recover_frame = ttk.Frame(notebook)
        notebook.add(recover_frame, text="Відновлення")
        
        ttk.Label(recover_frame, text="Захищений файл:").pack(anchor='w', padx=5, pady=(10,0))
        prot_frame = ttk.Frame(recover_frame)
        prot_frame.pack(fill='x', padx=5, pady=5)
        self.prot_label = tk.Label(prot_frame, text="Не обрано", fg="gray")
        self.prot_label.pack(side='left')
        ttk.Button(prot_frame, text="Обрати", command=self.select_protected).pack(side='right')
        
        ttk.Label(recover_frame, text="Пароль:").pack(anchor='w', padx=5)
        self.rec_pass = ttk.Entry(recover_frame, show="*")
        self.rec_pass.pack(fill='x', padx=5, pady=5)
        
        ttk.Button(recover_frame, text="Відновити файл", 
                  command=self.recover).pack(pady=10)
        
        self.recover_log = scrolledtext.ScrolledText(recover_frame, height=12)
        self.recover_log.pack(fill='both', expand=True, padx=5, pady=5)
        
        analytics_frame = ttk.Frame(notebook)
        notebook.add(analytics_frame, text="Аналітика")
        
        btn_frame = ttk.Frame(analytics_frame)
        btn_frame.pack(fill='x', padx=5, pady=5)
        ttk.Button(btn_frame, text="Звіт", command=self.show_report).pack(side='left', padx=2)
        ttk.Button(btn_frame, text="Графіки", command=self.show_plots).pack(side='left', padx=2)
        ttk.Button(btn_frame, text="Зберегти", command=self.save_report).pack(side='left', padx=2)
        
        self.analytics_text = scrolledtext.ScrolledText(analytics_frame, height=20)
        self.analytics_text.pack(fill='both', expand=True, padx=5, pady=5)
    
    def select_input(self):
        f = filedialog.askopenfilename(title="Файл для захисту")
        if f:
            self.input_file = f
            self.file_label.config(text=os.path.basename(f), fg="green")
    
    def select_container(self):
        f = filedialog.askopenfilename(title="Зображення-контейнер", 
                                       filetypes=[("PNG", "*.png")])
        if f:
            self.container = f
            self.cont_label.config(text=os.path.basename(f), fg="green")
    
    def select_protected(self):
        f = filedialog.askopenfilename(title="Захищений файл")
        if f:
            self.protected = f
            self.prot_label.config(text=os.path.basename(f), fg="green")
    
    def protect(self):
        if not self.input_file or not self.container:
            messagebox.showwarning("Увага", "Оберіть файл та контейнер")
            return
        
        password = self.pass_entry.get()
        if not password:
            messagebox.showwarning("Увага", "Введіть пароль")
            return
        
        output = filedialog.asksaveasfilename(defaultextension=".png", 
                                             filetypes=[("PNG", "*.png")])
        if not output:
            return
        
        self.protect_log.delete('1.0', 'end')
        try:
            self.protect_log.insert('end', "Шифрування...\n")
            self.root.update()
            result = self.system.protect_file(self.input_file, self.container, password, output)
            self.protect_log.insert('end', "Приховування...\n")
            self.protect_log.insert('end', f"\nГотово!\nHash: {result['hash'][:16]}...\n")
            messagebox.showinfo("Успіх", "Файл захищено")
        except Exception as e:
            messagebox.showerror("Помилка", str(e))
    
    def recover(self):
        if not self.protected:
            messagebox.showwarning("Увага", "Оберіть захищений файл")
            return
        
        password = self.rec_pass.get()
        if not password:
            messagebox.showwarning("Увага", "Введіть пароль")
            return
        
        output = filedialog.asksaveasfilename(title="Зберегти відновлений")
        if not output:
            return
        
        self.recover_log.delete('1.0', 'end')
        try:
            self.recover_log.insert('end', "Витягування...\n")
            self.root.update()
            result = self.system.recover_file(self.protected, password, output)
            if result['success']:
                self.recover_log.insert('end', "Дешифрування...\n")
                self.recover_log.insert('end', f"\nГотово!\nHash: {result['hash'][:16]}...\n")
                messagebox.showinfo("Успіх", "Файл відновлено")
            else:
                messagebox.showerror("Помилка", result['error'])
        except Exception as e:
            messagebox.showerror("Помилка", str(e))
    
    def show_report(self):
        report = self.system.analytics.generate_report()
        self.analytics_text.delete('1.0', 'end')
        self.analytics_text.insert('1.0', report)
    
    def show_plots(self):
        if self.system.analytics.metrics['operations']:
            self.system.analytics.plot_metrics()
            plt.show()
    
    def save_report(self):
        f = filedialog.asksaveasfilename(defaultextension=".txt", 
                                        filetypes=[("Text", "*.txt")])
        if f:
            with open(f, 'w', encoding='utf-8') as file:
                file.write(self.system.analytics.generate_report())
            self.system.analytics.plot_metrics(f.replace('.txt', '.png'))
            messagebox.showinfo("Успіх", "Звіт збережено")


if __name__ == "__main__":
    root = tk.Tk()
    app = SecuritySystemGUI(root)
    root.mainloop()
