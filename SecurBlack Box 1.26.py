import os
import sys
import hashlib
import json
import re
import tempfile
import shutil
import logging
from datetime import datetime
from pathlib import Path
from getpass import getpass
from dataclasses import dataclass, asdict
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import secrets

try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False

# Глобальные настройки
class Settings:
    SHOW_PASSWORD = False  # Показывать ли пароль при вводе
    SHOW_PASSWORD_STARS = True  # Показывать звездочки если пароль скрыт
    SHOW_CHAR_COUNT = True  # Показывать счетчик символов
    KEEP_TEMP_FILES = False  # Сохранять временные файлы
    ENABLE_LOGGING = False  # Включить логирование
    TEMP_FILES_DIR = "temp_encrypted"  # Папка для временных файлов
    EULA_ACCEPTED = False  # Флаг принятия пользовательского соглашения

# Файл для сохранения настроек
SETTINGS_FILE = "securblack_settings.json"

# Цвета для консоли
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    GRAY = '\033[90m'

def print_success(message):
    print(f"{Colors.GREEN}✓ {message}{Colors.RESET}")

def print_error(message):
    print(f"{Colors.RED}✗ {message}{Colors.RESET}")

def print_warning(message):
    print(f"{Colors.YELLOW}⚠ {message}{Colors.RESET}")

def print_info(message):
    print(f"{Colors.CYAN}ℹ {message}{Colors.RESET}")

@dataclass
class EncryptionConfig:
    iterations: int = 600000
    key_size: int = 32
    salt_size: int = 16
    nonce_size: int = 12
    algorithm: str = "AES-GCM"
    min_password_length: int = 12
    max_file_size_gb: int = 10
    
    @classmethod
    def load(cls, config_file: str = "securblack_config.json"):
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    data = json.load(f)
                return cls(**data)
            except Exception as e:
                print_warning(f"Ошибка загрузки конфигурации: {e}")
                return cls()
        return cls()
    
    def save(self, config_file: str = "securblack_config.json"):
        try:
            with open(config_file, 'w') as f:
                json.dump(asdict(self), f, indent=2)
        except Exception as e:
            print_error(f"Ошибка сохранения конфигурации: {e}")

def save_settings():
    """Сохранение настроек программы"""
    try:
        settings_data = {
            "show_password": Settings.SHOW_PASSWORD,
            "show_password_stars": Settings.SHOW_PASSWORD_STARS,
            "show_char_count": Settings.SHOW_CHAR_COUNT,
            "keep_temp_files": Settings.KEEP_TEMP_FILES,
            "enable_logging": Settings.ENABLE_LOGGING,
            "temp_files_dir": Settings.TEMP_FILES_DIR,
            "eula_accepted": Settings.EULA_ACCEPTED,
            "last_update": datetime.now().isoformat()
        }
        
        with open(SETTINGS_FILE, 'w', encoding='utf-8') as f:
            json.dump(settings_data, f, indent=2, ensure_ascii=False)
        
        return True
    except Exception as e:
        print_error(f"Ошибка сохранения настроек: {e}")
        return False

def load_settings():
    """Загрузка настроек программы"""
    try:
        if os.path.exists(SETTINGS_FILE):
            with open(SETTINGS_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            Settings.SHOW_PASSWORD = data.get("show_password", False)
            Settings.SHOW_PASSWORD_STARS = data.get("show_password_stars", True)
            Settings.SHOW_CHAR_COUNT = data.get("show_char_count", True)
            Settings.KEEP_TEMP_FILES = data.get("keep_temp_files", False)
            Settings.ENABLE_LOGGING = data.get("enable_logging", False)
            Settings.TEMP_FILES_DIR = data.get("temp_files_dir", "temp_encrypted")
            Settings.EULA_ACCEPTED = data.get("eula_accepted", False)
            
            return True
        return False
    except Exception as e:
        print_warning(f"Ошибка загрузки настроек: {e}")
        return False

class FileEncryptor:
    def __init__(self, config: EncryptionConfig = None):
        self.config = config or EncryptionConfig.load()
        self.iterations = self.config.iterations
        self.key_size = self.config.key_size
        self.salt_size = self.config.salt_size
        self.nonce_size = self.config.nonce_size
        self.max_file_size = self.config.max_file_size_gb * 1024 * 1024 * 1024
        
        # Создать папку для временных файлов если нужно
        if Settings.KEEP_TEMP_FILES:
            if not os.path.exists(Settings.TEMP_FILES_DIR):
                os.makedirs(Settings.TEMP_FILES_DIR, exist_ok=True)
        
        if Settings.ENABLE_LOGGING:
            self.setup_logging()
        else:
            self.logger = None
    
    def setup_logging(self):
        """Настройка системы логирования"""
        if not Settings.ENABLE_LOGGING:
            self.logger = None
            return
            
        log_dir = "logs"
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        log_file = os.path.join(log_dir, f"securblack_{datetime.now().strftime('%Y%m%d')}.log")
        
        self.logger = logging.getLogger("SecurBlack")
        self.logger.setLevel(logging.INFO)
        
        # Очистка старых обработчиков
        self.logger.handlers.clear()
        
        # Файловый обработчик
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(logging.INFO)
        file_formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)
        self.logger.addHandler(file_handler)
        
        if self.logger:
            self.logger.info("Инициализация FileEncryptor")
    
    def log(self, level: str, message: str):
        """Логирование с проверкой включения"""
        if self.logger:
            if level == 'info':
                self.logger.info(message)
            elif level == 'error':
                self.logger.error(message)
            elif level == 'warning':
                self.logger.warning(message)
    
    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Создание ключа из пароля с использованием PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.key_size,
            salt=salt,
            iterations=self.iterations,
            backend=default_backend()
        )
        return kdf.derive(password.encode('utf-8'))
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Вычисление SHA256 хэша файла"""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(65536), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            self.log('error', f"Ошибка вычисления хэша файла {file_path}: {e}")
            return ""
    
    def validate_password(self, password: str) -> tuple[bool, str]:
        """Проверка сложности пароля с возвратом причины"""
        if len(password) < self.config.min_password_length:
            return False, f"Пароль должен содержать минимум {self.config.min_password_length} символов"
        
        if not re.search(r'[A-Z]', password):
            return False, "Пароль должен содержать хотя бы одну заглавную букву"
        
        if not re.search(r'[a-z]', password):
            return False, "Пароль должен содержать хотя бы одну строчную букву"
        
        if not re.search(r'\d', password):
            return False, "Пароль должен содержать хотя бы одну цифру"
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False, "Пароль должен содержать хотя бы один специальный символ"
        
        # Проверка на простые пароли
        common_passwords = ["password", "123456", "qwerty", "admin", "welcome"]
        if password.lower() in common_passwords:
            return False, "Пароль слишком простой"
        
        return True, "Пароль надежен"
    
    def encrypt_file(self, file_path: str, password: str, create_backup: bool = True, keep_temp: bool = None) -> bool:
        """Шифрование файла с использованием AES-GCM"""
        if keep_temp is None:
            keep_temp = Settings.KEEP_TEMP_FILES
            
        self.log('info', f"Начало шифрования файла: {file_path}")
        
        try:
            # Проверка существования файла
            if not os.path.exists(file_path):
                print_error("Файл не найден")
                self.log('error', f"Файл не найден: {file_path}")
                return False
            
            # Проверка размера файла
            file_size = os.path.getsize(file_path)
            if file_size > self.max_file_size:
                print_error(f"Файл слишком большой (максимум {self.config.max_file_size_gb} GB)")
                self.log('error', f"Файл слишком большой: {file_path} ({file_size} байт)")
                return False
            
            # Проверка прав доступа
            if not os.access(file_path, os.R_OK):
                print_error("Нет доступа к файлу")
                self.log('error', f"Нет доступа к файлу: {file_path}")
                return False
            
            # Вычисление хэша исходного файла
            original_hash = self._calculate_file_hash(file_path)
            self.log('info', f"Хэш исходного файла {file_path}: {original_hash}")
            
            # Генерация соли и nonce
            salt = secrets.token_bytes(self.salt_size)
            nonce = secrets.token_bytes(self.nonce_size)
            
            # Создание ключа
            key = self._derive_key(password, salt)
            
            # Создание временного файла
            if keep_temp:
                # Сохраняем во временную папку
                temp_dir = Settings.TEMP_FILES_DIR
                temp_filename = os.path.basename(file_path) + '.enc.tmp'
                temp_path = os.path.join(temp_dir, temp_filename)
            else:
                # Временный файл в той же директории
                with tempfile.NamedTemporaryFile(delete=False, 
                                               dir=os.path.dirname(file_path) or '.',
                                               suffix='.tmp') as tmp_file:
                    temp_path = tmp_file.name
            
            try:
                # Чтение и шифрование файла
                with open(file_path, 'rb') as f:
                    plaintext = f.read()
                
                # Шифрование с использованием AES-GCM
                aesgcm = AESGCM(key)
                ciphertext = aesgcm.encrypt(nonce, plaintext, None)
                
                # Запись в файл
                with open(temp_path, 'wb') as f:
                    f.write(salt + nonce + ciphertext)
                
                # Путь для зашифрованного файла
                encrypted_path = file_path + '.enc'
                
                # Создание резервной копии
                if create_backup:
                    backup_path = file_path + '.backup'
                    try:
                        shutil.copy2(file_path, backup_path)
                        self.log('info', f"Создана резервная копия: {backup_path}")
                        print_info(f"Создана резервная копия: {backup_path}")
                    except Exception as e:
                        self.log('warning', f"Не удалось создать резервную копию: {e}")
                
                if keep_temp:
                    # Просто сохраняем зашифрованный файл во временной папке
                    print_success(f"Зашифрованный файл сохранен: {temp_path}")
                    self.log('info', f"Зашифрованный файл сохранен: {temp_path}")
                    return True
                else:
                    # Атомарная замена файла
                    shutil.move(temp_path, encrypted_path)
                    
                    # Удаление исходного файла
                    os.remove(file_path)
                    
                    # Вычисление хэша зашифрованного файла
                    encrypted_hash = self._calculate_file_hash(encrypted_path)
                    self.log('info', f"Хэш зашифрованного файла {encrypted_path}: {encrypted_hash}")
                    
                    print_success(f"Файл зашифрован: {encrypted_path}")
                    self.log('info', f"Файл успешно зашифрован: {encrypted_path}")
                    return True
                
            except Exception as e:
                # В случае ошибки удалить временный файл
                if not keep_temp and os.path.exists(temp_path):
                    os.unlink(temp_path)
                raise e
                
        except Exception as e:
            print_error(f"Ошибка шифрования: {e}")
            self.log('error', f"Ошибка шифрования файла {file_path}: {e}")
            return False
    
    def decrypt_file(self, file_path: str, password: str) -> bool:
        """Дешифрование файла"""
        self.log('info', f"Начало дешифрования файла: {file_path}")
        
        try:
            # Проверка расширения
            if not file_path.endswith('.enc'):
                print_error("Файл должен иметь расширение .enc")
                return False
            
            # Проверка существования файла
            if not os.path.exists(file_path):
                print_error("Файл не найден")
                return False
            
            # Проверка размера файла (должен быть хотя бы соль + nonce)
            file_size = os.path.getsize(file_path)
            if file_size < self.salt_size + self.nonce_size:
                print_error("Файл поврежден или слишком мал")
                self.log('error', f"Файл поврежден: {file_path}")
                return False
            
            # Создание временного файла
            with tempfile.NamedTemporaryFile(delete=False, 
                                           dir=os.path.dirname(file_path) or '.',
                                           suffix='.tmp') as tmp_file:
                temp_path = tmp_file.name
            
            try:
                # Чтение зашифрованного файла
                with open(file_path, 'rb') as f:
                    data = f.read()
                
                # Извлечение соли, nonce и зашифрованных данных
                salt = data[:self.salt_size]
                nonce = data[self.salt_size:self.salt_size + self.nonce_size]
                ciphertext = data[self.salt_size + self.nonce_size:]
                
                # Создание ключа
                key = self._derive_key(password, salt)
                
                # Дешифрование
                aesgcm = AESGCM(key)
                plaintext = aesgcm.decrypt(nonce, ciphertext, None)
                
                # Запись в временный файл
                with open(temp_path, 'wb') as f:
                    f.write(plaintext)
                
                # Путь для расшифрованного файла
                original_path = file_path[:-4]  # Убираем .enc
                
                # Атомарная замена файла
                shutil.move(temp_path, original_path)
                
                # Удаление зашифрованного файла
                os.remove(file_path)
                
                # Вычисление хэша расшифрованного файла
                decrypted_hash = self._calculate_file_hash(original_path)
                self.log('info', f"Хэш расшифрованного файла {original_path}: {decrypted_hash}")
                
                print_success(f"Файл расшифрован: {original_path}")
                self.log('info', f"Файл успешно расшифрован: {original_path}")
                return True
                
            except Exception as e:
                # В случае ошибки удалить временный файл
                if os.path.exists(temp_path):
                    os.unlink(temp_path)
                raise e
                
        except Exception as e:
            print_error(f"Ошибка дешифрования: {e}")
            self.log('error', f"Ошибка дешифрования файла {file_path}: {e}")
            return False
    
    def change_password(self, file_path: str, old_password: str, new_password: str) -> bool:
        """Изменение пароля файла"""
        self.log('info', f"Начало изменения пароля для файла: {file_path}")
        
        try:
            # Проверка расширения
            if not file_path.endswith('.enc'):
                print_error("Файл должен быть зашифрован")
                return False
            
            # Создание временного файла
            with tempfile.NamedTemporaryFile(delete=False, 
                                           dir=os.path.dirname(file_path) or '.',
                                           suffix='.tmp') as tmp_file:
                temp_path = tmp_file.name
            
            try:
                # Чтение зашифрованного файла
                with open(file_path, 'rb') as f:
                    data = f.read()
                
                # Извлечение соли, nonce и зашифрованных данных
                old_salt = data[:self.salt_size]
                nonce = data[self.salt_size:self.salt_size + self.nonce_size]
                ciphertext = data[self.salt_size + self.nonce_size:]
                
                # Создание старого ключа
                old_key = self._derive_key(old_password, old_salt)
                
                # Дешифрование старым ключом
                aesgcm = AESGCM(old_key)
                plaintext = aesgcm.decrypt(nonce, ciphertext, None)
                
                # Генерация новой соли и nonce
                new_salt = secrets.token_bytes(self.salt_size)
                new_nonce = secrets.token_bytes(self.nonce_size)
                new_key = self._derive_key(new_password, new_salt)
                
                # Шифрование новым ключом
                new_aesgcm = AESGCM(new_key)
                new_ciphertext = new_aesgcm.encrypt(new_nonce, plaintext, None)
                
                # Запись в временный файл
                with open(temp_path, 'wb') as f:
                    f.write(new_salt + new_nonce + new_ciphertext)
                
                # Атомарная замена файла
                shutil.move(temp_path, file_path)
                
                print_success("Пароль успешно изменен!")
                self.log('info', f"Пароль успешно изменен для файла: {file_path}")
                return True
                
            except Exception as e:
                # В случае ошибки удалить временный файл
                if os.path.exists(temp_path):
                    os.unlink(temp_path)
                raise e
                
        except Exception as e:
            print_error(f"Ошибка при изменении пароля: {e}")
            self.log('error', f"Ошибка изменения пароля для файла {file_path}: {e}")
            return False
    
    def encrypt_folder(self, folder_path: str, password: str, recursive: bool = True) -> bool:
        """Шифрование всех файлов в папке"""
        self.log('info', f"Начало шифрования папки: {folder_path}")
        
        try:
            folder_path = Path(folder_path)
            if not folder_path.exists() or not folder_path.is_dir():
                print_error("Папка не найдена")
                return False
            
            # Сбор всех файлов
            if recursive:
                files = list(folder_path.rglob('*'))
            else:
                files = list(folder_path.glob('*'))
            
            files = [str(f) for f in files if f.is_file() and not f.name.endswith('.enc')]
            
            if not files:
                print_warning("В папке нет файлов для шифрования")
                return True
            
            encrypted_count = 0
            
            # Прогресс-бар если доступен tqdm
            if TQDM_AVAILABLE and len(files) > 1:
                with tqdm(total=len(files), desc="Шифрование файлов", unit="файл") as pbar:
                    for file_path in files:
                        if self.encrypt_file(file_path, password, create_backup=False):
                            encrypted_count += 1
                        pbar.update(1)
            else:
                # Обычный цикл
                for i, file_path in enumerate(files, 1):
                    print_info(f"Обработка файла {i}/{len(files)}: {os.path.basename(file_path)}")
                    if self.encrypt_file(file_path, password, create_backup=False):
                        encrypted_count += 1
            
            print_success(f"Зашифровано файлов: {encrypted_count}/{len(files)}")
            self.log('info', f"Зашифровано файлов в папке {folder_path}: {encrypted_count}/{len(files)}")
            return True
            
        except Exception as e:
            print_error(f"Ошибка шифрования папки: {e}")
            self.log('error', f"Ошибка шифрования папки {folder_path}: {e}")
            return False
    
    def decrypt_folder(self, folder_path: str, password: str, recursive: bool = True) -> bool:
        """Дешифрование всех файлов в папке"""
        self.log('info', f"Начало дешифрования папки: {folder_path}")
        
        try:
            folder_path = Path(folder_path)
            if not folder_path.exists() or not folder_path.is_dir():
                print_error("Папка не найдена")
                return False
            
            # Сбор всех зашифрованных файлов
            if recursive:
                files = list(folder_path.rglob('*.enc'))
            else:
                files = list(folder_path.glob('*.enc'))
            
            files = [str(f) for f in files if f.is_file()]
            
            if not files:
                print_warning("В папке нет зашифрованных файлов")
                return True
            
            decrypted_count = 0
            
            # Прогресс-бар если доступен tqdm
            if TQDM_AVAILABLE and len(files) > 1:
                with tqdm(total=len(files), desc="Дешифрование файлов", unit="файл") as pbar:
                    for file_path in files:
                        if self.decrypt_file(file_path, password):
                            decrypted_count += 1
                        pbar.update(1)
            else:
                # Обычный цикл
                for i, file_path in enumerate(files, 1):
                    print_info(f"Обработка файла {i}/{len(files)}: {os.path.basename(file_path)}")
                    if self.decrypt_file(file_path, password):
                        decrypted_count += 1
            
            print_success(f"Расшифровано файлов: {decrypted_count}/{len(files)}")
            self.log('info', f"Расшифровано файлов в папке {folder_path}: {decrypted_count}/{len(files)}")
            return True
            
        except Exception as e:
            print_error(f"Ошибка дешифрования папки: {e}")
            self.log('error', f"Ошибка дешифрования папки {folder_path}: {e}")
            return False
    
    def change_password_folder(self, folder_path: str, old_password: str, new_password: str, recursive: bool = True) -> bool:
        """Изменение пароля для всех файлов в папке"""
        self.log('info', f"Начало изменения пароля для папки: {folder_path}")
        
        try:
            folder_path = Path(folder_path)
            if not folder_path.exists() or not folder_path.is_dir():
                print_error("Папка не найдена")
                return False
            
            # Сбор всех зашифрованных файлов
            if recursive:
                files = list(folder_path.rglob('*.enc'))
            else:
                files = list(folder_path.glob('*.enc'))
            
            files = [str(f) for f in files if f.is_file()]
            
            if not files:
                print_warning("В папке нет зашифрованных файлов")
                return True
            
            changed_count = 0
            
            # Прогресс-бар если доступен tqdm
            if TQDM_AVAILABLE and len(files) > 1:
                with tqdm(total=len(files), desc="Изменение паролей", unit="файл") as pbar:
                    for file_path in files:
                        if self.change_password(file_path, old_password, new_password):
                            changed_count += 1
                        pbar.update(1)
            else:
                # Обычный цикл
                for i, file_path in enumerate(files, 1):
                    print_info(f"Обработка файла {i}/{len(files)}: {os.path.basename(file_path)}")
                    if self.change_password(file_path, old_password, new_password):
                        changed_count += 1
            
            print_success(f"Пароль изменен для {changed_count}/{len(files)} файлов")
            self.log('info', f"Пароль изменен для файлов в папке {folder_path}: {changed_count}/{len(files)}")
            return True
            
        except Exception as e:
            print_error(f"Ошибка изменения пароля: {e}")
            self.log('error', f"Ошибка изменения пароля для папки {folder_path}: {e}")
            return False

def get_password_input(prompt: str) -> str:
    """Ввод пароля с настройками отображения"""
    print()
    
    if Settings.SHOW_PASSWORD:
        # Показывать пароль полностью
        print(f"{Colors.GRAY}[Режим: видимый ввод]{Colors.RESET}")
        password = input(prompt)
        if Settings.SHOW_CHAR_COUNT:
            print(f"{Colors.GRAY}[Символов: {len(password)}]{Colors.RESET}")
        return password
    else:
        # Скрытый ввод
        print(f"{Colors.GRAY}[Режим: скрытый ввод]{Colors.RESET}")
        
        if Settings.SHOW_PASSWORD_STARS:
            # Показывать звездочки
            if os.name == 'nt':  # Windows
                import msvcrt
                password = []
                print(prompt, end='', flush=True)
                while True:
                    ch = msvcrt.getch()
                    if ch in (b'\r', b'\n'):
                        print()
                        break
                    elif ch == b'\x08':  # Backspace
                        if password:
                            password.pop()
                            print('\b \b', end='', flush=True)
                            if Settings.SHOW_CHAR_COUNT:
                                # Обновить счетчик
                                print(f"\r{prompt}{'*' * len(password)}", end='', flush=True)
                    else:
                        password.append(ch.decode('utf-8', errors='ignore'))
                        print('*', end='', flush=True)
                    
                    # Показать счетчик символов
                    if Settings.SHOW_CHAR_COUNT:
                        count_text = f" [{len(password)}]"
                        print(f"\r{prompt}{'*' * len(password)}{Colors.GRAY}{count_text}{Colors.RESET}", end='', flush=True)
                
                return ''.join(password)
            else:  # Linux/Mac
                import termios
                import tty
                password = []
                print(prompt, end='', flush=True)
                fd = sys.stdin.fileno()
                old_settings = termios.tcgetattr(fd)
                try:
                    tty.setraw(fd)
                    while True:
                        ch = sys.stdin.read(1)
                        if ch == '\r' or ch == '\n':
                            print()
                            break
                        elif ch == '\x7f' or ch == '\b':  # Backspace
                            if password:
                                password.pop()
                                print('\b \b', end='', flush=True)
                                if Settings.SHOW_CHAR_COUNT:
                                    # Обновить счетчик
                                    print(f"\r{prompt}{'*' * len(password)}", end='', flush=True)
                        else:
                            password.append(ch)
                            print('*', end='', flush=True)
                        
                        # Показать счетчик символов
                        if Settings.SHOW_CHAR_COUNT:
                            count_text = f" [{len(password)}]"
                            print(f"\r{prompt}{'*' * len(password)}{Colors.GRAY}{count_text}{Colors.RESET}", end='', flush=True)
                finally:
                    termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
                return ''.join(password)
        else:
            # Полностью скрытый ввод (без звездочек)
            return getpass(prompt)

def clear_screen():
    """Очистка экрана"""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    """Баннер программы"""
    banner = f"""
{Colors.BOLD}{Colors.MAGENTA}
╔═══════════════════════════════════════════╗
║          SecurBlack Box 1.26             ║
╚═══════════════════════════════════════════╝
{Colors.RESET}
    """
    print(banner)

def show_eula():
    """Отображение пользовательского соглашения"""
    
    # Проверяем, было ли уже принято соглашение
    if Settings.EULA_ACCEPTED:
        return True
    
    clear_screen()
    
    eula_text = f"""
{Colors.BOLD}{Colors.MAGENTA}
╔═══════════════════════════════════════════╗
║          SecurBlack Box 1.26             ║
╚═══════════════════════════════════════════╝
{Colors.RESET}

{Colors.BOLD}{Colors.YELLOW}ПОЛЬЗОВАТЕЛЬСКОЕ СОГЛАШЕНИЕ{Colors.RESET}

Перед использованием SecurBlack Box 1.26 вы должны принять 
пользовательское соглашение.

{Colors.BOLD}ВАЖНАЯ ИНФОРМАЦИЯ О БЕЗОПАСНОСТИ:{Colors.RESET}

{Colors.GREEN}✓ ГАРАНТИЯ КОНФИДЕНЦИАЛЬНОСТИ:{Colors.RESET}
1. Программа НЕ передает и НЕ отправляет данные в интернет
2. Все операции выполняются локально на вашем компьютере
3. Пароли и ключи шифрования НЕ покидают ваше устройство
4. Исходный код открыт для проверки

{Colors.BOLD}Настройки по умолчанию:{Colors.RESET}
• Логирование: {Colors.RED}ВЫКЛЮЧЕНО{Colors.RESET}
• Сохранение временных файлов: {Colors.RED}ВЫКЛЮЧЕНО{Colors.RESET}
• Режим ввода пароля: {Colors.YELLOW}ЗВЕЗДОЧКИ{Colors.RESET}
• Соглашение сохраняется после принятия

{Colors.BOLD}Используемые библиотеки:{Colors.RESET}
• cryptography - только для локального шифрования
• tqdm - только для отображения прогресса (опционально)
• стандартные библиотеки Python

{Colors.BOLD}Важные предупреждения:{Colors.RESET}
1. Вы используете программу на свой страх и риск
2. Автор не несет ответственности за потерю данных
3. Всегда создавайте резервные копии важных файлов
4. Храните пароли в безопасном месте
5. Программа не требует подключения к интернету

{Colors.BOLD}Полный текст пользовательского соглашения:{Colors.RESET}
{Colors.BLUE}https://sites.google.com/view/securblackbox/пользовательское-соглашение{Colors.RESET}

{Colors.YELLOW}Вы принимаете пользовательское соглашение?{Colors.RESET}
"""
    print(eula_text)
    
    while True:
        choice = input(f"{Colors.CYAN}Введите 'Y' для принятия или 'N' для отказа (Y/N): {Colors.RESET}").strip().upper()
        
        if choice == 'Y':
            # Сохраняем факт принятия соглашения
            Settings.EULA_ACCEPTED = True
            save_settings()  # Сохраняем настройки
            
            print_success("Соглашение принято. Больше не будет запрашиваться.")
            input("\nНажмите Enter для продолжения...")
            return True
        elif choice == 'N':
            print_error("Вы отказались от пользовательского соглашения. Программа будет закрыта.")
            input("\nНажмите Enter для выхода...")
            return False
        else:
            print_error("Неверный ввод. Пожалуйста, введите Y или N")

def main_menu():
    """Главное меню"""
    encryptor = FileEncryptor()
    
    while True:
        clear_screen()
        print_banner()
        print(f"{Colors.BOLD}{Colors.CYAN}ГЛАВНОЕ МЕНЮ{Colors.RESET}")
        print(f"{Colors.BOLD}1.{Colors.RESET} Работа с файлом")
        print(f"{Colors.BOLD}2.{Colors.RESET} Работа с папкой")
        print(f"{Colors.BOLD}3.{Colors.RESET} Настройки")
        print(f"{Colors.BOLD}4.{Colors.RESET} Настройки безопасности")
        print(f"{Colors.BOLD}5.{Colors.RESET} О программе")
        print(f"{Colors.BOLD}6.{Colors.RESET} Выйти")
        print()
        
        choice = input(f"{Colors.YELLOW}Выберите действие (1-6): {Colors.RESET}").strip()
        
        if choice == '1':
            file_menu(encryptor)
        elif choice == '2':
            folder_menu(encryptor)
        elif choice == '3':
            settings_menu(encryptor)
        elif choice == '4':
            security_settings_menu()
        elif choice == '5':
            about_menu()
        elif choice == '6':
            print()
            print_success("До свидания!")
            break
        else:
            print_error("Неверный выбор!")
            input("Нажмите Enter для продолжения...")

def file_menu(encryptor):
    """Меню работы с файлом"""
    while True:
        clear_screen()
        print_banner()
        print(f"{Colors.BOLD}{Colors.CYAN}РАБОТА С ФАЙЛОМ{Colors.RESET}")
        print(f"{Colors.BOLD}1.{Colors.RESET} Зашифровать файл")
        print(f"{Colors.BOLD}2.{Colors.RESET} Расшифровать файл")
        print(f"{Colors.BOLD}3.{Colors.RESET} Изменить пароль файла")
        print(f"{Colors.BOLD}4.{Colors.RESET} Назад")
        print()
        
        choice = input(f"{Colors.YELLOW}Выберите действие (1-4): {Colors.RESET}").strip()
        
        if choice == '1':
            print()
            file_path = input(f"{Colors.CYAN}Введите путь к файлу: {Colors.RESET}").strip()
            if not os.path.exists(file_path):
                print_error("Файл не найден!")
            else:
                # Спросить о сохранении временного файла
                keep_temp = None
                if Settings.KEEP_TEMP_FILES:
                    choice_temp = input(f"{Colors.CYAN}Сохранить временный зашифрованный файл? (y/n) [{Colors.GREEN}y{Colors.CYAN}]: {Colors.RESET}").strip().lower()
                    if choice_temp == 'y' or choice_temp == '':
                        keep_temp = True
                        print_info("Зашифрованный файл будет сохранен в папке 'temp_encrypted'")
                    else:
                        keep_temp = False
                
                while True:
                    print()
                    password = get_password_input(f"{Colors.CYAN}Придумайте пароль: {Colors.RESET}")
                    confirm = get_password_input(f"{Colors.CYAN}Повторите пароль: {Colors.RESET}")
                    
                    if password == confirm:
                        is_valid, message = encryptor.validate_password(password)
                        if is_valid:
                            encryptor.encrypt_file(file_path, password, keep_temp=keep_temp)
                            break
                        else:
                            print_error(message)
                    else:
                        print_error("Пароли не совпадают!")
            
            input("\nНажмите Enter для продолжения...")
            
        elif choice == '2':
            print()
            file_path = input(f"{Colors.CYAN}Введите путь к зашифрованному файлу: {Colors.RESET}").strip()
            if not os.path.exists(file_path):
                print_error("Файл не найден!")
            else:
                password = get_password_input(f"{Colors.CYAN}Введите пароль: {Colors.RESET}")
                encryptor.decrypt_file(file_path, password)
            
            input("\nНажмите Enter для продолжения...")
            
        elif choice == '3':
            print()
            file_path = input(f"{Colors.CYAN}Введите путь к зашифрованному файлу: {Colors.RESET}").strip()
            if not os.path.exists(file_path):
                print_error("Файл не найден!")
            else:
                old_password = get_password_input(f"{Colors.CYAN}Введите текущий пароль: {Colors.RESET}")
                print()
                
                while True:
                    new_password = get_password_input(f"{Colors.CYAN}Введите новый пароль: {Colors.RESET}")
                    confirm = get_password_input(f"{Colors.CYAN}Повторите новый пароль: {Colors.RESET}")
                    
                    if new_password == confirm:
                        is_valid, message = encryptor.validate_password(new_password)
                        if is_valid:
                            encryptor.change_password(file_path, old_password, new_password)
                            break
                        else:
                            print_error(message)
                    else:
                        print_error("Новые пароли не совпадают!")
            
            input("\nНажмите Enter для продолжения...")
            
        elif choice == '4':
            break
        else:
            print_error("Неверный выбор!")
            input("Нажмите Enter для продолжения...")

def folder_menu(encryptor):
    """Меню работы с папкой"""
    while True:
        clear_screen()
        print_banner()
        print(f"{Colors.BOLD}{Colors.CYAN}РАБОТА С ПАПКОЙ{Colors.RESET}")
        print(f"{Colors.BOLD}1.{Colors.RESET} Зашифровать папку")
        print(f"{Colors.BOLD}2.{Colors.RESET} Расшифровать папку")
        print(f"{Colors.BOLD}3.{Colors.RESET} Изменить пароль для папки")
        print(f"{Colors.BOLD}4.{Colors.RESET} Назад")
        print()
        
        choice = input(f"{Colors.YELLOW}Выберите действие (1-4): {Colors.RESET}").strip()
        
        if choice == '1':
            print()
            folder_path = input(f"{Colors.CYAN}Введите путь к папке: {Colors.RESET}").strip()
            if not os.path.exists(folder_path) or not os.path.isdir(folder_path):
                print_error("Папка не найдена!")
            else:
                recursive = input(f"{Colors.CYAN}Рекурсивно (включая подпапки)? (y/n): {Colors.RESET}").strip().lower() == 'y'
                
                # Спросить о сохранении временных файлов
                keep_temp = None
                if Settings.KEEP_TEMP_FILES:
                    choice_temp = input(f"{Colors.CYAN}Сохранять временные зашифрованные файлы? (y/n) [{Colors.GREEN}y{Colors.CYAN}]: {Colors.RESET}").strip().lower()
                    if choice_temp == 'y' or choice_temp == '':
                        keep_temp = True
                        print_info("Зашифрованные файлы будут сохранены в папке 'temp_encrypted'")
                    else:
                        keep_temp = False
                
                while True:
                    print()
                    password = get_password_input(f"{Colors.CYAN}Придумайте пароль: {Colors.RESET}")
                    confirm = get_password_input(f"{Colors.CYAN}Повторите пароль: {Colors.RESET}")
                    
                    if password == confirm:
                        is_valid, message = encryptor.validate_password(password)
                        if is_valid:
                            # Модифицируем encrypt_folder для поддержки keep_temp
                            if keep_temp:
                                # Специальная обработка для сохранения временных файлов
                                success = encrypt_folder_with_temp(encryptor, folder_path, password, recursive)
                            else:
                                success = encryptor.encrypt_folder(folder_path, password, recursive)
                            break
                        else:
                            print_error(message)
                    else:
                        print_error("Пароли не совпадают!")
            
            input("\nНажмите Enter для продолжения...")
            
        elif choice == '2':
            print()
            folder_path = input(f"{Colors.CYAN}Введите путь к папке: {Colors.RESET}").strip()
            if not os.path.exists(folder_path) or not os.path.isdir(folder_path):
                print_error("Папка не найдена!")
            else:
                recursive = input(f"{Colors.CYAN}Рекурсивно (включая подпапки)? (y/n): {Colors.RESET}").strip().lower() == 'y'
                password = get_password_input(f"{Colors.CYAN}Введите пароль: {Colors.RESET}")
                encryptor.decrypt_folder(folder_path, password, recursive)
            
            input("\nНажмите Enter для продолжения...")
            
        elif choice == '3':
            print()
            folder_path = input(f"{Colors.CYAN}Введите путь к папке: {Colors.RESET}").strip()
            if not os.path.exists(folder_path) or not os.path.isdir(folder_path):
                print_error("Папка не найдена!")
            else:
                recursive = input(f"{Colors.CYAN}Рекурсивно (включая подпапки)? (y/n): {Colors.RESET}").strip().lower() == 'y'
                old_password = get_password_input(f"{Colors.CYAN}Введите текущий пароль: {Colors.RESET}")
                print()
                
                while True:
                    new_password = get_password_input(f"{Colors.CYAN}Введите новый пароль: {Colors.RESET}")
                    confirm = get_password_input(f"{Colors.CYAN}Повторите новый пароль: {Colors.RESET}")
                    
                    if new_password == confirm:
                        is_valid, message = encryptor.validate_password(new_password)
                        if is_valid:
                            encryptor.change_password_folder(folder_path, old_password, new_password, recursive)
                            break
                        else:
                            print_error(message)
                    else:
                        print_error("Новые пароли не совпадают!")
            
            input("\nНажмите Enter для продолжения...")
            
        elif choice == '4':
            break
        else:
            print_error("Неверный выбор!")
            input("Нажмите Enter для продолжения...")

def encrypt_folder_with_temp(encryptor, folder_path: str, password: str, recursive: bool = True) -> bool:
    """Шифрование папки с сохранением временных файлов"""
    try:
        folder_path = Path(folder_path)
        if not folder_path.exists() or not folder_path.is_dir():
            print_error("Папка не найдена")
            return False
        
        # Сбор всех файлов
        if recursive:
            files = list(folder_path.rglob('*'))
        else:
            files = list(folder_path.glob('*'))
        
        files = [str(f) for f in files if f.is_file() and not f.name.endswith('.enc')]
        
        if not files:
            print_warning("В папке нет файлов для шифрования")
            return True
        
        encrypted_count = 0
        
        # Прогресс-бар если доступен tqdm
        if TQDM_AVAILABLE and len(files) > 1:
            with tqdm(total=len(files), desc="Шифрование файлов", unit="файл") as pbar:
                for file_path in files:
                    if encryptor.encrypt_file(file_path, password, create_backup=False, keep_temp=True):
                        encrypted_count += 1
                    pbar.update(1)
        else:
            # Обычный цикл
            for i, file_path in enumerate(files, 1):
                print_info(f"Обработка файла {i}/{len(files)}: {os.path.basename(file_path)}")
                if encryptor.encrypt_file(file_path, password, create_backup=False, keep_temp=True):
                    encrypted_count += 1
        
        print_success(f"Зашифровано файлов: {encrypted_count}/{len(files)}")
        print_info(f"Временные файлы сохранены в папке: {Settings.TEMP_FILES_DIR}")
        if encryptor.logger:
            encryptor.log('info', f"Зашифровано файлов в папке {folder_path}: {encrypted_count}/{len(files)}")
        return True
        
    except Exception as e:
        print_error(f"Ошибка шифрования папки: {e}")
        if encryptor.logger:
            encryptor.log('error', f"Ошибка шифрования папки {folder_path}: {e}")
        return False

def settings_menu(encryptor):
    """Меню настроек шифрования"""
    while True:
        clear_screen()
        print_banner()
        print(f"{Colors.BOLD}{Colors.CYAN}НАСТРОЙКИ ШИФРОВАНИЯ{Colors.RESET}")
        print(f"{Colors.BOLD}1.{Colors.RESET} Показать текущие настройки")
        print(f"{Colors.BOLD}2.{Colors.RESET} Изменить минимальную длину пароля")
        print(f"{Colors.BOLD}3.{Colors.RESET} Изменить количество итераций PBKDF2")
        print(f"{Colors.BOLD}4.{Colors.RESET} Изменить максимальный размер файла (GB)")
        print(f"{Colors.BOLD}5.{Colors.RESET} Сохранить настройки")
        print(f"{Colors.BOLD}6.{Colors.RESET} Сбросить настройки")
        print(f"{Colors.BOLD}7.{Colors.RESET} Назад")
        print()
        
        choice = input(f"{Colors.YELLOW}Выберите действие (1-7): {Colors.RESET}").strip()
        
        if choice == '1':
            print()
            print(f"{Colors.BOLD}Текущие настройки:{Colors.RESET}")
            print(f"  • Алгоритм: {encryptor.config.algorithm}")
            print(f"  • Итерации PBKDF2: {encryptor.config.iterations:,}")
            print(f"  • Минимальная длина пароля: {encryptor.config.min_password_length}")
            print(f"  • Максимальный размер файла: {encryptor.config.max_file_size_gb} GB")
            print(f"  • Размер ключа: {encryptor.config.key_size} байт")
            print(f"  • Размер соли: {encryptor.config.salt_size} байт")
            print(f"  • Размер nonce: {encryptor.config.nonce_size} байт")
            
            input("\nНажмите Enter для продолжения...")
            
        elif choice == '2':
            print()
            try:
                new_length = int(input(f"{Colors.CYAN}Введите новую минимальную длину пароля (8-32): {Colors.RESET}").strip())
                if 8 <= new_length <= 32:
                    encryptor.config.min_password_length = new_length
                    print_success("Настройка сохранена!")
                else:
                    print_error("Длина должна быть от 8 до 32 символов")
            except ValueError:
                print_error("Введите корректное число")
            
            input("\nНажмите Enter для продолжения...")
            
        elif choice == '3':
            print()
            try:
                new_iterations = int(input(f"{Colors.CYAN}Введите новое количество итераций (100000-1000000): {Colors.RESET}").strip())
                if 100000 <= new_iterations <= 1000000:
                    encryptor.config.iterations = new_iterations
                    encryptor.iterations = new_iterations
                    print_success("Настройка сохранена!")
                else:
                    print_error("Количество итераций должно быть от 100,000 до 1,000,000")
            except ValueError:
                print_error("Введите корректное число")
            
            input("\nНажмите Enter для продолжения...")
            
        elif choice == '4':
            print()
            try:
                new_size = int(input(f"{Colors.CYAN}Введите новый максимальный размер файла (1-100 GB): {Colors.RESET}").strip())
                if 1 <= new_size <= 100:
                    encryptor.config.max_file_size_gb = new_size
                    encryptor.max_file_size = new_size * 1024 * 1024 * 1024
                    print_success("Настройка сохранена!")
                else:
                    print_error("Размер должен быть от 1 до 100 GB")
            except ValueError:
                print_error("Введите корректное число")
            
            input("\nНажмите Enter для продолжения...")
            
        elif choice == '5':
            encryptor.config.save()
            print_success("Настройки сохранены в файл securblack_config.json")
            input("\nНажмите Enter для продолжения...")
            
        elif choice == '6':
            encryptor.config = EncryptionConfig()
            encryptor.iterations = encryptor.config.iterations
            encryptor.max_file_size = encryptor.config.max_file_size_gb * 1024 * 1024 * 1024
            print_success("Настройки сброшены к значениям по умолчанию")
            input("\nНажмите Enter для продолжения...")
            
        elif choice == '7':
            break
        else:
            print_error("Неверный выбор!")
            input("Нажмите Enter для продолжения...")

def security_settings_menu():
    """Меню настроек безопасности"""
    while True:
        clear_screen()
        print_banner()
        print(f"{Colors.BOLD}{Colors.CYAN}НАСТРОЙКИ БЕЗОПАСНОСТИ{Colors.RESET}")
        
        # Показать текущие настройки
        print(f"\n{Colors.BOLD}Текущие настройки:{Colors.RESET}")
        logging_status = f"{Colors.GREEN}ВКЛЮЧЕНО{Colors.RESET}" if Settings.ENABLE_LOGGING else f"{Colors.RED}ВЫКЛЮЧЕНО{Colors.RESET}"
        temp_status = f"{Colors.GREEN}ВКЛЮЧЕНО{Colors.RESET}" if Settings.KEEP_TEMP_FILES else f"{Colors.RED}ВЫКЛЮЧЕНО{Colors.RESET}"
        eula_status = f"{Colors.GREEN}ПРИНЯТО{Colors.RESET}" if Settings.EULA_ACCEPTED else f"{Colors.RED}НЕ ПРИНЯТО{Colors.RESET}"
        
        if Settings.SHOW_PASSWORD:
            password_mode = f"{Colors.GREEN}ВИДИМЫЙ{Colors.RESET}"
        elif Settings.SHOW_PASSWORD_STARS:
            password_mode = f"{Colors.YELLOW}ЗВЕЗДОЧКИ{Colors.RESET}"
        else:
            password_mode = f"{Colors.RED}СКРЫТЫЙ{Colors.RESET}"
            
        char_count_status = f"{Colors.GREEN}ВКЛЮЧЕНО{Colors.RESET}" if Settings.SHOW_CHAR_COUNT else f"{Colors.RED}ВЫКЛЮЧЕНО{Colors.RESET}"
        
        print(f"  1. Логирование: {logging_status}")
        print(f"  2. Сохранение временных файлов: {temp_status}")
        print(f"  3. Режим ввода пароля: {password_mode}")
        print(f"  4. Счетчик символов: {char_count_status}")
        print(f"  5. Пользовательское соглашение: {eula_status}")
        print(f"  6. Информация о безопасности")
        print(f"  7. Сбросить все настройки")
        print(f"  8. Назад")
        print()
        
        choice = input(f"{Colors.YELLOW}Выберите настройку для изменения (1-8): {Colors.RESET}").strip()
        
        if choice == '1':
            print()
            new_setting = input(f"{Colors.CYAN}Включить логирование? (y/n) [{Colors.RED}n{Colors.CYAN}]: {Colors.RESET}").strip().lower()
            if new_setting == 'y':
                Settings.ENABLE_LOGGING = True
                print_success("Логирование включено")
            else:
                Settings.ENABLE_LOGGING = False
                print_success("Логирование выключено")
            
            save_settings()  # Сохраняем изменения
            input("\nНажмите Enter для продолжения...")
            
        elif choice == '2':
            print()
            new_setting = input(f"{Colors.CYAN}Сохранять временные зашифрованные файлы? (y/n) [{Colors.RED}n{Colors.CYAN}]: {Colors.RESET}").strip().lower()
            if new_setting == 'y':
                Settings.KEEP_TEMP_FILES = True
                # Создать папку если ее нет
                if not os.path.exists(Settings.TEMP_FILES_DIR):
                    os.makedirs(Settings.TEMP_FILES_DIR, exist_ok=True)
                print_success("Сохранение временных файлов включено")
                print_info(f"Файлы будут сохраняться в: {Settings.TEMP_FILES_DIR}")
            else:
                Settings.KEEP_TEMP_FILES = False
                print_success("Сохранение временных файлов выключено")
            
            save_settings()  # Сохраняем изменения
            input("\nНажмите Enter для продолжения...")
            
        elif choice == '3':
            print()
            print(f"{Colors.BOLD}Режимы ввода пароля:{Colors.RESET}")
            print(f"  1. Видимый ввод (символы видны)")
            print(f"  2. Звездочки (показываются *)")
            print(f"  3. Скрытый ввод (ничего не видно)")
            
            mode = input(f"\n{Colors.CYAN}Выберите режим (1-3) [{Colors.YELLOW}2{Colors.CYAN}]: {Colors.RESET}").strip()
            
            if mode == '1' or mode == '':
                Settings.SHOW_PASSWORD = True
                Settings.SHOW_PASSWORD_STARS = False
                print_success("Установлен видимый режим ввода")
            elif mode == '2':
                Settings.SHOW_PASSWORD = False
                Settings.SHOW_PASSWORD_STARS = True
                print_success("Установлен режим звездочек")
            elif mode == '3':
                Settings.SHOW_PASSWORD = False
                Settings.SHOW_PASSWORD_STARS = False
                print_success("Установлен скрытый режим ввода")
            else:
                print_error("Неверный выбор")
            
            save_settings()  # Сохраняем изменения
            input("\nНажмите Enter для продолжения...")
            
        elif choice == '4':
            print()
            new_setting = input(f"{Colors.CYAN}Показывать счетчик символов при вводе пароля? (y/n) [{Colors.GREEN}y{Colors.CYAN}]: {Colors.RESET}").strip().lower()
            if new_setting == 'y' or new_setting == '':
                Settings.SHOW_CHAR_COUNT = True
                print_success("Счетчик символов включен")
            else:
                Settings.SHOW_CHAR_COUNT = False
                print_success("Счетчик символов выключен")
            
            save_settings()  # Сохраняем изменения
            input("\nНажмите Enter для продолжения...")
            
        elif choice == '5':
            print()
            print(f"{Colors.BOLD}Статус пользовательского соглашения:{Colors.RESET}")
            print(f"  • Текущий статус: {eula_status}")
            print(f"  • Дата принятия: сохранена в настройках")
            print()
            
            if not Settings.EULA_ACCEPTED:
                choice_eula = input(f"{Colors.CYAN}Принять пользовательское соглашение сейчас? (y/n): {Colors.RESET}").strip().lower()
                if choice_eula == 'y':
                    # Показываем соглашение заново
                    if show_eula():
                        save_settings()
            else:
                choice_eula = input(f"{Colors.CYAN}Сбросить принятие соглашения? (y/n): {Colors.RESET}").strip().lower()
                if choice_eula == 'y':
                    Settings.EULA_ACCEPTED = False
                    save_settings()
                    print_success("Принятие соглашения сброшено. При следующем запуске будет запрошено.")
            
            input("\nНажмите Enter для продолжения...")
            
        elif choice == '6':
            print()
            print(f"{Colors.BOLD}{Colors.GREEN}ИНФОРМАЦИЯ О БЕЗОПАСНОСТИ{Colors.RESET}")
            print()
            print(f"{Colors.BOLD}Логирование:{Colors.RESET}")
            print("  • Записывает операции в файлы в папке 'logs/'")
            print("  • Содержит: время, действие, путь к файлу, хэши")
            print("  • НЕ содержит пароли или ключи шифрования")
            print("  • По умолчанию: ВЫКЛЮЧЕНО")
            print()
            print(f"{Colors.BOLD}Временные файлы:{Colors.RESET}")
            print("  • Сохраняются в папке 'temp_encrypted/'")
            print("  • Только зашифрованные версии файлов")
            print("  • Исходные файлы НЕ сохраняются")
            print("  • По умолчанию: ВЫКЛЮЧЕНО")
            print()
            print(f"{Colors.BOLD}Пользовательское соглашение:{Colors.RESET}")
            print("  • Запрашивается только при первом запуске")
            print("  • Сохраняется в файле настроек")
            print("  • Можно сбросить в настройках безопасности")
            print()
            print(f"{Colors.BOLD}Режимы ввода пароля:{Colors.RESET}")
            print("  • Видимый: все символы видны (небезопасно)")
            print("  • Звездочки: показываются * (рекомендуется)")
            print("  • Скрытый: ничего не видно (максимальная безопасность)")
            
            input("\nНажмите Enter для продолжения...")
            
        elif choice == '7':
            print()
            confirm = input(f"{Colors.RED}Вы уверены, что хотите сбросить ВСЕ настройки? (y/n): {Colors.RESET}").strip().lower()
            if confirm == 'y':
                # Сбрасываем все настройки к значениям по умолчанию
                Settings.SHOW_PASSWORD = False
                Settings.SHOW_PASSWORD_STARS = True
                Settings.SHOW_CHAR_COUNT = True
                Settings.KEEP_TEMP_FILES = False
                Settings.ENABLE_LOGGING = False
                Settings.TEMP_FILES_DIR = "temp_encrypted"
                # НЕ сбрасываем EULA_ACCEPTED - это отдельно
                
                # Удаляем файл настроек
                if os.path.exists(SETTINGS_FILE):
                    os.remove(SETTINGS_FILE)
                
                print_success("Все настройки сброшены к значениям по умолчанию")
            else:
                print_info("Сброс настроек отменен")
            
            input("\nНажмите Enter для продолжения...")
            
        elif choice == '8':
            break
        else:
            print_error("Неверный выбор!")
            input("Нажмите Enter для продолжения...")

def about_menu():
    """Меню о программе"""
    clear_screen()
    print_banner()
    
    about_text = f"""
{Colors.BOLD}{Colors.CYAN}О ПРОГРАММЕ{Colors.RESET}

{Colors.BOLD}SecurBlack Box 1.26{Colors.RESET}
Программа для шифрования файлов и папок

{Colors.BOLD}Основные функции:{Colors.RESET}
• Шифрование файлов и папок
• Дешифрование файлов с расширением .enc
• Изменение пароля зашифрованных файлов
• Шифрование рекурсивно по всем подпапкам

{Colors.BOLD}Технологии:{Colors.RESET}
• Алгоритм: AES-256-GCM
• Ключевая деривация: PBKDF2-HMAC-SHA256
• Итерации PBKDF2: 600,000
• Размер ключа: 256 бит (32 байта)
• Размер соли: 128 бит (16 байт)
• Размер nonce: 96 бит (12 байт)

{Colors.BOLD}Особенности безопасности:{Colors.RESET}
✓ Работает полностью оффлайн
✓ Нет передачи данных в интернет
✓ Пароли не покидают устройство
✓ Использует только локальное шифрование
✓ Открытый исходный код

{Colors.BOLD}Настройки безопасности:{Colors.RESET}
• Логирование: {'ВКЛЮЧЕНО' if Settings.ENABLE_LOGGING else 'ВЫКЛЮЧЕНО'}
• Временные файлы: {'ВКЛЮЧЕНО' if Settings.KEEP_TEMP_FILES else 'ВЫКЛЮЧЕНО'}
• Пользовательское соглашение: {'ПРИНЯТО' if Settings.EULA_ACCEPTED else 'НЕ ПРИНЯТО'}

{Colors.BOLD}Авторские права:{Colors.RESET}
© 2024 SecurBlack Box. Все права защищены.
Программа предоставляется "как есть".

{Colors.BOLD}Ссылка на пользовательское соглашение:{Colors.RESET}
{Colors.BLUE}https://sites.google.com/view/securblackbox{Colors.RESET}

{Colors.GRAY}Версия: 1.26{Colors.RESET}
"""
    print(about_text)
    
    input(f"\n{Colors.CYAN}Нажмите Enter для возврата в главное меню...{Colors.RESET}")

def check_dependencies():
    """Проверка зависимостей"""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return True
    except ImportError:
        print_error("Не установлена библиотека cryptography")
        print("Установите её командой: pip install cryptography")
        return False

if __name__ == "__main__":
    try:
        # Загружаем настройки
        load_settings()
        
        # Проверка зависимостей
        if not check_dependencies():
            sys.exit(1)
        
        # Показать пользовательское соглашение только если оно не принято
        if not Settings.EULA_ACCEPTED:
            if not show_eula():
                sys.exit(0)
        else:
            # Если соглашение уже принято, просто показываем баннер
            clear_screen()
            print_banner()
            print_info("Пользовательское соглашение уже принято ранее.")
            input("\nНажмите Enter для продолжения...")
        
        # Запустить главное меню
        main_menu()
        
    except KeyboardInterrupt:
        print()
        print_warning("Программа прервана пользователем")
    except Exception as e:
        print_error(f"Критическая ошибка: {e}")
        input("Нажмите Enter для выхода...")