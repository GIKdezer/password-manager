import json
import base64
import os
from getpass import getpass

import typer
from rich.console import Console
from rich.table import Table
from argon2.low_level import hash_secret_raw, Type
from cryptography.fernet import Fernet

# --- КОНФИГУРАЦИЯ ---
DB_FILE = "vault.json"
app = typer.Typer()
console = Console()

# --- ЛОГИКА ШИФРОВАНИЯ ---

def derive_key(master_password: str, salt: bytes) -> bytes:
    raw_key = hash_secret_raw(
        secret=master_password.encode(),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        type=Type.ID
    )
    return base64.urlsafe_b64encode(raw_key)

def encrypt_data(data: str, key: bytes) -> str:
    f = Fernet(key)
    return f.encrypt(data.encode()).decode()

def decrypt_data(token: str, key: bytes) -> str:
    f = Fernet(key)
    return f.decrypt(token.encode()).decode()

# --- РАБОТА С ХРАНИЛИЩЕМ ---

def save_vault(salt: bytes, entries: list):
    data = {
        "salt": base64.b64encode(salt).decode('utf-8'),
        "entries": entries
    }
    with open(DB_FILE, "w") as f:
        json.dump(data, f, indent=4)

def load_vault():
    if not os.path.exists(DB_FILE):
        return None, []
    with open(DB_FILE, "r") as f:
        data = json.load(f)
        salt = base64.b64decode(data["salt"])
        return salt, data["entries"]

def add_entry(service, login, plain_password, master_pwd):
    salt, entries = load_vault()
    if salt is None:
        salt = os.urandom(16)
    
    key = derive_key(master_pwd, salt)
    encrypted_pwd = encrypt_data(plain_password, key)
    
    entries.append({
        "service": service,
        "login": login,
        "password": encrypted_pwd
    })
    save_vault(salt, entries)

# --- CLI КОМАНДЫ ---

@app.command()
def add():
    """Добавить новый пароль"""
    service = typer.prompt("Введите название сервиса")
    login = typer.prompt("Введите логин")
    password = getpass("Введите пароль от сервиса: ")
    master_pwd = getpass("Введите ваш Мастер-пароль: ")
    
    add_entry(service, login, password, master_pwd)
    console.print(f"[bold green]Успешно![/bold green] Данные для {service} зашифрованы.")

@app.command()
@app.command()
def ls():
    """Показать список всех сервисов"""
    salt, entries = load_vault()
    if not entries:
        console.print("[yellow]База пуста.[/yellow]")
        return

    master_pwd = getpass("Введите Мастер-пароль: ")
    key = derive_key(master_pwd, salt)
    
    table = Table(title="Ваши доступы")
    table.add_column("Сервис", style="cyan")
    table.add_column("Логин", style="magenta")
    table.add_column("Пароль", style="green")

    for entry in entries:
        try:
            # Пытаемся расшифровать каждую запись отдельно
            decrypted_pass = decrypt_data(entry["password"], key)
            table.add_row(entry["service"], entry["login"], decrypted_pass)
        except Exception:
            # Если пароль не подошел к этой конкретной записи
            table.add_row(entry["service"], entry["login"], "[red]Ошибка ключа (другой пароль?)[/red]")
    
    console.print(table)

if __name__ == "__main__":
    app()