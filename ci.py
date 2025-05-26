# cryptomaster.py
import os
import sys
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding as asym_padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography import x509
from cryptography.x509.oid import NameOID
import questionary

# --- Шифрование ---
def encrypt_aes(data: bytes, password: str) -> bytes:
    """Шифрование AES-256-CBC с PBKDF2"""
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )
    key = kdf.derive(password.encode())
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    return salt + iv + encryptor.update(padded_data) + encryptor.finalize()

def decrypt_aes(encrypted: bytes, password: str) -> bytes:
    """Дешифрование AES-256-CBC"""
    salt, iv, ct = encrypted[:16], encrypted[16:32], encrypted[32:]
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )
    key = kdf.derive(password.encode())
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted = decryptor.update(ct) + decryptor.finalize()
    return unpadder.update(decrypted) + unpadder.finalize()

# --- Ключи ---
def generate_rsa_key(key_size=2048):
    """Генерация RSA ключа"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pem.decode()

# --- Подписи ---
def sign_data(data: bytes, private_key_pem: str) -> bytes:
    """Подпись данных RSA-PSS"""
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(),
        password=None
    )
    return private_key.sign(
        data,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

# --- Сертификаты ---
def create_self_signed_cert():
    """Создание самоподписанного сертификата"""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.COMMON_NAME, "CryptoMaster Cert")
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)
    ).sign(private_key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.PEM).decode()

# --- Интерфейс ---
def show_menu():
    while True:
        action = questionary.select(
            "CryptoMaster - Выберите действие:",
            choices=[
                "🔒 Шифрование файла (AES)",
                "🔓 Дешифрование файла (AES)",
                "🔑 Генерация RSA ключа",
                "📝 Создать сертификат",
                "🚪 Выход"
            ]
        ).ask()

        if action == "🔒 Шифрование файла (AES)":
            path = questionary.path("Укажите путь к файлу:").ask()
            password = questionary.password("Введите пароль:").ask()
            with open(path, "rb") as f:
                encrypted = encrypt_aes(f.read(), password)
            with open(path + ".enc", "wb") as f:
                f.write(encrypted)
            print(f"✅ Файл сохранен как {path}.enc")

        elif action == "🔓 Дешифрование файла (AES)":
            path = questionary.path("Укажите файл для дешифровки:").ask()
            password = questionary.password("Введите пароль:").ask()
            with open(path, "rb") as f:
                decrypted = decrypt_aes(f.read(), password)
            output_path = path.replace(".enc", ".dec")
            with open(output_path, "wb") as f:
                f.write(decrypted)
            print(f"✅ Файл расшифрован: {output_path}")

        elif action == "🔑 Генерация RSA ключа":
            key = generate_rsa_key()
            print("🔑 Приватный ключ RSA:\n" + key)

        elif action == "📝 Создать сертификат":
            cert = create_self_signed_cert()
            print("📜 Сертификат X.509:\n" + cert)

        elif action == "🚪 Выход":
            sys.exit(0)

if __name__ == "__main__":
    print("🛡️ CryptoMaster - Криптографический инструментарий")
    try:
        show_menu()
    except KeyboardInterrupt:
        print("\n🚪 Выход из программы")
