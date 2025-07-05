import customtkinter as ctk
import threading
import random
import requests
import hashlib
import time
import os
import json
import binascii
import ecdsa
import base58
import psutil
import multiprocessing
from datetime import datetime
from tkinter import filedialog
from pathlib import Path
from mnemonic import Mnemonic
import socket
from bip44 import Wallet  # برای استفاده از BIP44

# تنظیمات ظاهری
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

SUCCESS_FILE_JSON = "results/results.json"
SUCCESS_FILE_TXT = "results/results.txt"
SUCCESS_FILE_CSV = "results/results.csv"
MAX_CORES = min(multiprocessing.cpu_count(), 16)  # محدود کردن به حداکثر 16 هسته

# بارگذاری زبان‌ها به صورت دستی
LANGUAGES = [
    "english", "chinese_simplified", "chinese_traditional", "french", "italian", "japanese", 
    "korean", "spanish", "portuguese", "czech", "polish", "arabic", "russian", "turkish"
]

def load_words(language="english"):
    mnemonic = Mnemonic(language)
    return mnemonic.wordlist

WORDS = load_words("english")  # زبان پیش فرض انگلیسی

def generate_mnemonic(num):
    return " ".join(random.choice(WORDS) for _ in range(num))

def hmac_sha512(mnemonic, passphrase):
    return f"{mnemonic} {passphrase}"

def generate_private_key(hmac_input):
    return hashlib.sha256(hmac_input.encode("utf-8")).hexdigest().upper()

def private_to_public(private_key):
    private_bytes = binascii.unhexlify(private_key)
    signing_key = ecdsa.SigningKey.from_string(private_bytes, curve=ecdsa.SECP256k1)
    verifying_key = signing_key.verifying_key
    return '04' + binascii.hexlify(verifying_key.to_string()).decode()

def public_to_address(public_key, address_type="legacy"):
    sha = hashlib.sha256(binascii.unhexlify(public_key)).digest()
    ripe = hashlib.new("ripemd160", sha).digest()

    if address_type == "legacy":
        payload = b"\x00" + ripe
    elif address_type == "p2sh":
        payload = b"\x05" + ripe
    elif address_type == "bech32":
        payload = b"\x00" + ripe
    else:
        return None

    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    address_bytes = payload + checksum

    if address_type == "bech32":
        return "bc1" + base58.b58encode(address_bytes).decode()[1:]  # fake bech32
    return base58.b58encode(address_bytes).decode()

def private_to_wif(private_key):
    extended_key = "80" + private_key
    first_sha = hashlib.sha256(binascii.unhexlify(extended_key)).digest()
    second_sha = hashlib.sha256(first_sha).digest()
    final_key = extended_key + second_sha[:4].hex()
    return base58.b58encode(binascii.unhexlify(final_key)).decode()

def check_balance(address):
    try:
        url = f"https://api.blockcypher.com/v1/btc/main/addrs/{address}/balance"
        response = requests.get(url)
        data = response.json()
        return data.get("balance", 0) / 1e8
    except Exception as e:
        print(f"Error checking balance: {e}")
        return -1

# تابع برای بررسی وضعیت اتصال اینترنت
def check_internet_connection():
    try:
        sockets = [
            ("www.google.com", 80),
            ("1.1.1.1", 53),
            ("8.8.8.8", 53)
        ]
        for host, port in sockets:
            try:
                socket.create_connection((host, port), timeout=3)
                return True
            except (socket.timeout, socket.gaierror):
                continue
        return False
    except Exception as e:
        print(f"Error checking internet connection: {e}")
        return False

class BTCApp:
    def __init__(self, root):
        self.root = root
        self.root.title("BTC Hack Pro v4.04")
        self.root.geometry("800x800")

        self.running = False
        self.attempts = 0
        self.successes = 0
        self.total_balance = 0
        self.start_time = None
        self.num_threads = 1
        self.selected_language = "english"
        self.num_words = 12  # تعداد پیش‌فرض کلمات
        self.words = load_words(self.selected_language)

        self.auto_resources_enabled = False
        self.load_settings()

        self.setup_ui()

    def load_settings(self):
        """بارگذاری تنظیمات ذخیره شده از فایل"""
        if os.path.exists("settings.json"):
            with open("settings.json", "r", encoding="utf-8") as f:
                settings = json.load(f)
                self.num_words = settings.get("num_words", 12)
                self.num_threads = settings.get("num_threads", 1)
                self.selected_language = settings.get("language", "english")
                self.words = load_words(self.selected_language)
                self.auto_resources_enabled = settings.get("auto_resources_enabled", False)

    def save_settings(self):
        """ذخیره تنظیمات به فایل"""
        settings = {
            "num_words": self.num_words,
            "num_threads": self.num_threads,
            "language": self.selected_language,
            "auto_resources_enabled": self.auto_resources_enabled
        }
        with open("settings.json", "w", encoding="utf-8") as f:
            json.dump(settings, f, indent=2)

    def setup_ui(self):
        self.frame = ctk.CTkFrame(master=self.root)
        self.frame.pack(pady=20, padx=20, fill="both", expand=True)

        self.balance_label = ctk.CTkLabel(self.frame, text="Successful Addresses: 0 | Total Balance: 0 BTC", font=("Arial", 14))
        self.balance_label.pack(pady=10)

        self.language_combo = ctk.CTkComboBox(self.frame, values=LANGUAGES, command=self.change_language)
        self.language_combo.set(self.selected_language)
        self.language_combo.pack(pady=10)

        self.mnemonic_combo = ctk.CTkComboBox(self.frame, values=[str(n) for n in (3, 6, 9, 12, 15, 18, 21, 24)],
                                              command=self.change_num_words)
        self.mnemonic_combo.set(str(self.num_words))
        self.mnemonic_combo.pack(pady=10)

        self.cores_combo = ctk.CTkComboBox(self.frame, values=[str(n) for n in range(1, MAX_CORES+1)], command=self.change_cores)
        self.cores_combo.set("1")
        self.cores_combo.pack(pady=10)

        self.auto_resources_check = ctk.CTkCheckBox(self.frame, text="Auto resource management (RAM/CPU)", command=self.toggle_auto_resources)
        self.auto_resources_check.set(self.auto_resources_enabled)
        self.auto_resources_check.pack(pady=10)

        self.start_btn = ctk.CTkButton(self.frame, text="Start", command=self.toggle_start)
        self.start_btn.pack(pady=10)

        self.internet_label = ctk.CTkLabel(self.frame, text="🌐 Internet Status: Disconnected", font=("Arial", 12))
        self.internet_label.pack(pady=5)

        self.output_box = ctk.CTkTextbox(self.frame, height=300)
        self.output_box.pack(padx=10, pady=10, fill="both", expand=True)

        self.progress_label = ctk.CTkLabel(self.frame, text="", font=("Arial", 12))
        self.progress_label.pack()

        self.sys_label = ctk.CTkLabel(self.frame, text="🖥 CPU: 0% | 🧠 RAM: 0%")
        self.sys_label.pack(pady=5)
        
        self.update_system_stats()
        self.update_internet_status()

    def change_language(self, value):
        self.selected_language = value
        self.words = load_words(value)  
        self.save_settings()  
        self.log(f"Language changed to {value}")  
        self.update_mnemonic_example()

    def update_mnemonic_example(self):
        """ به روز رسانی نمونه کلمات """
        mnemonic_example = generate_mnemonic(self.num_words)
        self.log(f"Example mnemonic in {self.selected_language}: {mnemonic_example}")

    def change_num_words(self, value):
        self.num_words = int(value)  
        self.save_settings()  
        self.log(f"Number of words changed to {value}")  

    def change_cores(self, value):
        self.num_threads = int(value)

    def toggle_auto_resources(self):
        """ فعال/غیرفعال کردن مدیریت خودکار منابع """
        self.auto_resources_enabled = not self.auto_resources_enabled
        self.save_settings()  
        self.log(f"Auto resource management is {'enabled' if self.auto_resources_enabled else 'disabled'}")

    def toggle_start(self):
        if not self.running:
            self.running = True
            self.start_btn.configure(text="Stop")
            threading.Thread(target=self.run_search, daemon=True).start()
        else:
            self.running = False
            self.start_btn.configure(text="Start")

    def log(self, text):
        self.output_box.insert("end", text + "\n")
        self.output_box.see("end")

    def update_status(self):
        elapsed = (datetime.now() - self.start_time).seconds if self.start_time else 0
        try_rate = self.attempts / elapsed if elapsed else 0
        percent = f"{(self.successes / self.attempts) * 100:.2f}%" if self.attempts else "0%"
        self.progress_label.configure(text=f"⏳ Attempts: {self.attempts} | ✅ Success: {self.successes} ({percent}) | ⏱ Time: {elapsed}s | ⚡ Rate: {try_rate:.2f}/s")

    def update_system_stats(self):
        cpu = psutil.cpu_percent(interval=None)
        ram = psutil.virtual_memory().percent

        cpu_color = "green" if cpu < 50 else "orange" if cpu < 80 else "red"
        ram_color = "green" if ram < 50 else "orange" if ram < 80 else "red"

        self.sys_label.configure(
            text=f"🖥 CPU: {cpu}% | 🧠 RAM: {ram}%",
            text_color=(cpu_color if cpu > ram else ram_color)
        )
        
        if self.auto_resources_enabled:
            self.adjust_resources(cpu, ram)

        self.root.after(1000, self.update_system_stats)

    def adjust_resources(self, cpu, ram):
        """ تنظیم منابع خودکار """
        if cpu < 50 and ram < 50 and self.num_threads < MAX_CORES:
            self.num_threads += 1
            self.log(f"Increasing threads to {self.num_threads} due to low CPU/RAM usage.")
        elif cpu > 80 or ram > 80 and self.num_threads > 1:
            self.num_threads -= 1
            self.log(f"Decreasing threads to {self.num_threads} due to high CPU/RAM usage.")

    def update_internet_status(self):
        if check_internet_connection():
            self.internet_label.configure(text="🌐 Internet Status: Connected", text_color="green")
        else:
            self.internet_label.configure(text="🌐 Internet Status: Disconnected", text_color="red")
        self.root.after(5000, self.update_internet_status)

    def run_search(self):
        self.start_time = datetime.now()
        checked_addresses = set()

        with multiprocessing.Pool(processes=self.num_threads) as pool:
            while self.running:
                self.attempts += 1
                mnemonic = generate_mnemonic(self.num_words)
                passphrase = ""
                hmac_input = hmac_sha512(mnemonic, passphrase)
                priv_key = generate_private_key(hmac_input)
                pub_key = private_to_public(priv_key)

                for address_type in ["legacy", "p2sh", "bech32"]:
                    address = public_to_address(pub_key, address_type)
                    if address not in checked_addresses:
                        checked_addresses.add(address)
                        wif = private_to_wif(priv_key)
                        balance = check_balance(address)

                        if balance > 0:
                            self.successes += 1
                            self.total_balance += balance
                            self.log(f"Found: {address} | Balance: {balance} BTC | WIF: {wif}")

                self.update_status()
                time.sleep(1)  

        self.running = False
        self.start_btn.configure(text="Start")
        self.log("Search stopped.")
        self.attempts = 0
        self.successes = 0
        self.total_balance = 0
        self.start_time = None
        self.num_threads = 1
        self.selected_language = "english"
        self.num_words = 12  # تعداد پیش‌فرض کلمات
        self.words = load_words(self.selected_language)

        self.load_settings()  # بارگذاری تنظیمات ذخیره شده

        self.setup_ui()

    def load_settings(self):
        """بارگذاری تنظیمات ذخیره شده از فایل"""
        if os.path.exists("settings.json"):
            with open("settings.json", "r", encoding="utf-8") as f:
                settings = json.load(f)
                self.num_words = settings.get("num_words", 12)
                self.num_threads = settings.get("num_threads", 1)
                self.selected_language = settings.get("language", "english")
                self.words = load_words(self.selected_language)

    def save_settings(self):
        """ذخیره تنظیمات به فایل"""
        settings = {
            "num_words": self.num_words,
            "num_threads": self.num_threads,
            "language": self.selected_language
        }
        with open("settings.json", "w", encoding="utf-8") as f:
            json.dump(settings, f, indent=2)

    def setup_ui(self):
        self.frame = ctk.CTkFrame(master=self.root)
        self.frame.pack(pady=20, padx=20, fill="both", expand=True)

        self.balance_label = ctk.CTkLabel(self.frame, text="Successful Addresses: 0 | Total Balance: 0 BTC", font=("Arial", 14))
        self.balance_label.pack(pady=10)

        self.language_combo = ctk.CTkComboBox(self.frame, values=LANGUAGES, command=self.change_language)
        self.language_combo.set(self.selected_language)
        self.language_combo.pack(pady=10)

        self.mnemonic_combo = ctk.CTkComboBox(self.frame, values=[str(n) for n in (3, 6, 9, 12, 15, 18, 21, 24)],
                                              command=self.change_num_words)
        self.mnemonic_combo.set(str(self.num_words))
        self.mnemonic_combo.pack(pady=10)

        self.cores_combo = ctk.CTkComboBox(self.frame, values=[str(n) for n in range(1, MAX_CORES+1)], command=self.change_cores)
        self.cores_combo.set("1")
        self.cores_combo.pack(pady=10)

        self.start_btn = ctk.CTkButton(self.frame, text="Start", command=self.toggle_start)
        self.start_btn.pack(pady=10)

        self.internet_label = ctk.CTkLabel(self.frame, text="🌐 Internet Status: Disconnected", font=("Arial", 12))
        self.internet_label.pack(pady=5)

        self.output_box = ctk.CTkTextbox(self.frame, height=300)
        self.output_box.pack(padx=10, pady=10, fill="both", expand=True)

        self.progress_label = ctk.CTkLabel(self.frame, text="", font=("Arial", 12))
        self.progress_label.pack()

        self.sys_label = ctk.CTkLabel(self.frame, text="🖥 CPU: 0% | 🧠 RAM: 0%")
        self.sys_label.pack(pady=5)
        
        self.update_system_stats()
        self.update_internet_status()

    def change_language(self, value):
        self.selected_language = value
        self.words = load_words(value)  # به روز رسانی لیست کلمات با زبان جدید
        self.save_settings()  # ذخیره تنظیمات جدید
        self.log(f"Language changed to {value}")  # لاگ تغییر زبان
        self.update_mnemonic_example()  # به‌روزرسانی نمونه کلمات تولید شده

    def update_mnemonic_example(self):
        """ به روز رسانی نمونه کلمات برای نشان دادن زبان جدید """
        mnemonic_example = generate_mnemonic(self.num_words)
        self.log(f"Example mnemonic in {self.selected_language}: {mnemonic_example}")

    def change_num_words(self, value):
        self.num_words = int(value)  # بروز رسانی تعداد کلمات
        self.save_settings()  # ذخیره تنظیمات جدید
        self.log(f"Number of words changed to {value}")  # لاگ تغییر تعداد کلمات

    def change_cores(self, value):
        self.num_threads = int(value)

    def toggle_start(self):
        if not self.running:
            self.running = True
            self.start_btn.configure(text="Stop")
            threading.Thread(target=self.run_search, daemon=True).start()
        else:
            self.running = False
            self.start_btn.configure(text="Start")

    def log(self, text):
        self.output_box.insert("end", text + "\n")
        self.output_box.see("end")

    def update_status(self):
        elapsed = (datetime.now() - self.start_time).seconds if self.start_time else 0
        try_rate = self.attempts / elapsed if elapsed else 0
        percent = f"{(self.successes / self.attempts) * 100:.2f}%" if self.attempts else "0%"
        self.progress_label.configure(text=f"⏳ Attempts: {self.attempts} | ✅ Success: {self.successes} ({percent}) | ⏱ Time: {elapsed}s | ⚡ Rate: {try_rate:.2f}/s")

    def update_system_stats(self):
        cpu = psutil.cpu_percent(interval=None)
        ram = psutil.virtual_memory().percent

        cpu_color = "green" if cpu < 50 else "orange" if cpu < 80 else "red"
        ram_color = "green" if ram < 50 else "orange" if ram < 80 else "red"

        self.sys_label.configure(
            text=f"🖥 CPU: {cpu}% | 🧠 RAM: {ram}%",
            text_color=(cpu_color if cpu > ram else ram_color)
        )
        self.root.after(1000, self.update_system_stats)

    def update_internet_status(self):
        if check_internet_connection():
            self.internet_label.configure(text="🌐 Internet Status: Connected", text_color="green")
        else:
            self.internet_label.configure(text="🌐 Internet Status: Disconnected", text_color="red")
        self.root.after(5000, self.update_internet_status)

    def run_search(self):
        self.start_time = datetime.now()
        checked_addresses = set()

        with multiprocessing.Pool(processes=self.num_threads) as pool:
            while self.running:
                self.attempts += 1
                mnemonic = generate_mnemonic(self.num_words)
                passphrase = ""
                hmac_input = hmac_sha512(mnemonic, passphrase)
                priv_key = generate_private_key(hmac_input)
                pub_key = private_to_public(priv_key)

                # پردازش آدرس‌ها
                for address_type in ["legacy", "p2sh", "bech32"]:
                    address = public_to_address(pub_key, address_type)
                    if address not in checked_addresses:
                        checked_addresses.add(address)
                        wif = private_to_wif(priv_key)
                        self.log(f"Generated {address_type} address: {address} | Mnemonic: {mnemonic}")
                        pool.apply_async(self.check_balance_and_log, (address, mnemonic, passphrase, priv_key, wif, address_type))

                self.update_status()

    def check_balance_and_log(self, address, mnemonic, passphrase, priv_key, wif, address_type):
        balance = check_balance(address)
        if balance > 0:
            self.successes += 1
            self.total_balance += balance
            self.log(f"Success: {address_type} - {address} - Balance: {balance} BTC")
            self.update_status()
            self.log("🎉 FOUND MONEY!")
            self.save_success(mnemonic, passphrase, priv_key, address, wif, balance)

    def save_success(self, mnemonic, passphrase, priv, addr, wif, balance):
        result = {
            "mnemonic": mnemonic,
            "passphrase": passphrase,
            "private_key": priv,
            "address": addr,
            "wif": wif,
            "balance": balance
        }

        os.makedirs("results", exist_ok=True)

        # ذخیره در JSON
        with open(SUCCESS_FILE_JSON, "a", encoding="utf-8") as f:
            json.dump(result, f, indent=2)
        
        # ذخیره در CSV
        with open(SUCCESS_FILE_CSV, "a", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([mnemonic, addr, balance])

        # ذخیره در TXT
        with open(SUCCESS_FILE_TXT, "a", encoding="utf-8") as f:
            f.write(f"{mnemonic} | {addr} | {balance} BTC\n")
            
# ✅ جلوگیری از اجرای رابط گرافیکی در فرآیندهای subprocess
if __name__ == "__main__":
    multiprocessing.freeze_support()  # برای ویندوز
    root = ctk.CTk()
    app = BTCApp(root)
    root.mainloop()
