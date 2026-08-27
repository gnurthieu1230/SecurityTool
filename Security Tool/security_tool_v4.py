#!/usr/bin/env python3
import os
import re
import ssl
import sys
import json
import time
import socket
import base64
import hashlib
import secrets
import string
import platform
import subprocess
import urllib.request
import urllib.error
import urllib.parse
from pathlib import Path
from datetime import datetime

try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes as _hashes
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

def derive_fernet_key(password: str, salt: bytes, iterations: int = 200_000) -> bytes:
    """Dẫn xuất khóa AES (qua Fernet) từ mật khẩu bằng PBKDF2-SHA256.
    Dùng chung cho mã hóa file, quản lý mật khẩu, và ghi chú bảo mật."""
    kdf = PBKDF2HMAC(algorithm=_hashes.SHA256(), length=32, salt=salt, iterations=iterations)
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

PASSWORD_DB = "passwords.json"
NOTES_FILE = "secure_notes.enc"
DISK_LOG = "disk_log.json"
CONFIG_FILE = "config.json"          # KHÔNG commit file này lên git — chứa API key
INTEGRITY_DB = "integrity_baseline.json"

def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def save_config(cfg):
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)

def get_vt_api_key():
    """Ưu tiên biến môi trường VT_API_KEY, sau đó tới config.json.
    Nếu chưa có, hỏi người dùng và lưu lại (chỉ lưu local, không hardcode trong code)."""
    key = os.environ.get("VT_API_KEY", "").strip()
    if key:
        return key
    cfg = load_config()
    key = cfg.get("virustotal_api_key", "").strip()
    if key:
        return key
    print("\n  [!] Chưa cấu hình VirusTotal API Key.")
    print("      Cách 1: export VT_API_KEY=... (khuyến nghị, không lưu ra file)")
    print("      Cách 2: nhập ngay đây để lưu vào config.json (nhớ thêm config.json vào .gitignore)")
    entered = input("  Nhập API key (Enter để bỏ qua): ").strip()
    if entered:
        cfg["virustotal_api_key"] = entered
        save_config(cfg)
        return entered
    return ""

def get_platform():
    if "ANDROID_ROOT" in os.environ or os.path.exists("/system/bin/pm"):
        return "android"
    return platform.system().lower()

def run_cmd(cmd, timeout=10):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip()
    except:
        return ""

def print_header(title):
    print("\n" + "="*55)
    print(f"  {title}")
    print("="*55)

def calc_hash(path):
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while chunk := f.read(8192):
                md5.update(chunk)
                sha256.update(chunk)
        return md5.hexdigest(), sha256.hexdigest()
    except:
        return None, None

def check_virustotal(sha256):
    api_key = get_vt_api_key()
    if not api_key:
        print("  [VirusTotal] Chưa cấu hình API Key")
        return
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    headers = {"x-apikey": api_key}
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=12) as resp:
            data = json.loads(resp.read().decode())
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        print(f"  [VirusTotal] Malicious: {malicious} | Suspicious: {suspicious}")
        if malicious > 0:
            print(f"  → CẢNH BÁO: {malicious} engine phát hiện mã độc!")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            print("  [VirusTotal] File chưa có trên VirusTotal")
        elif e.code == 401:
            print("  [VirusTotal] API Key không hợp lệ")
        elif e.code == 429:
            print("  [VirusTotal] Rate limit")
        else:
            print(f"  [VirusTotal] Lỗi HTTP {e.code}")
    except Exception as e:
        print(f"  [VirusTotal] Lỗi: {e}")

def batch_hash_vt():
    print_header("1. Hash hàng loạt + VirusTotal")
    path = input("Đường dẫn file/thư mục: ").strip().strip('"')
    if not os.path.exists(path):
        print("Không tồn tại")
        return
    files = [path] if os.path.isfile(path) else list(Path(path).rglob("*.*"))[:25]
    for f in files:
        f = str(f)
        md5, sha = calc_hash(f)
        print(f"\nFile: {os.path.basename(f)}")
        print(f"  MD5   : {md5}")
        print(f"  SHA256: {sha}")
        if sha:
            check_virustotal(sha)

def monitor_process():
    print_header("2. Theo dõi Process đáng ngờ")
    if get_platform() == "windows":
        print(run_cmd("tasklist /FO TABLE /NH"))
    else:
        print("--- RAM cao ---")
        print(run_cmd("ps aux --sort=-%mem | head -n 15"))
        print("\n--- CPU cao ---")
        print(run_cmd("ps aux --sort=-%cpu | head -n 10"))

def check_startup():
    print_header("3. Kiểm tra Startup Programs")
    plat = get_platform()
    if plat == "windows":
        print(run_cmd('reg query "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"'))
        print(run_cmd('reg query "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"'))
    elif plat == "linux":
        print(run_cmd("systemctl --user list-unit-files --state=enabled 2>/dev/null | head -n 15"))
        print(run_cmd("crontab -l 2>/dev/null") or "Không có crontab")
    elif plat == "android":
        print(run_cmd("dumpsys package | grep -i RECEIVE_BOOT_COMPLETED | head -n 15"))
    else:
        print("Chưa hỗ trợ đầy đủ")

def scan_usb_suspicious():
    print_header("4. Quét USB/ổ cứng tìm file đáng ngờ")
    path = input("Đường dẫn ổ đĩa/USB: ").strip().strip('"')
    if not os.path.exists(path):
        print("Không tồn tại")
        return
    exts = {".exe", ".dll", ".bat", ".cmd", ".vbs", ".js", ".ps1", ".scr", ".apk", ".jar"}
    found = 0
    for root, _, files in os.walk(path):
        for name in files:
            if os.path.splitext(name)[1].lower() in exts:
                full = os.path.join(root, name)
                try:
                    print(f"  [?] {full} ({os.path.getsize(full):,} bytes)")
                    found += 1
                except:
                    pass
                if found >= 50:
                    print("\nĐã đạt giới hạn.")
                    return
    print(f"\nTổng cộng: {found} file.")

def clean_junk():
    print_header("5. Dọn rác đa nền tảng")
    plat = get_platform()
    targets = [os.path.expandvars(r"%TEMP%"), os.path.expandvars(r"%TMP%")] if plat == "windows" else ["/tmp", str(Path.home()/".cache")]
    deleted = 0
    now = time.time()
    for t in targets:
        if not os.path.exists(t): continue
        for root, _, files in os.walk(t):
            for name in files:
                p = os.path.join(root, name)
                try:
                    if now - os.path.getmtime(p) > 2*86400:
                        os.remove(p)
                        deleted += 1
                except: pass
    print(f"Đã xóa khoảng {deleted} file cũ.")

def disk_monitor():
    print_header("6. Theo dõi dung lượng ổ đĩa")
    out = run_cmd("wmic logicaldisk get size,freespace,caption" if get_platform()=="windows" else "df -h")
    print(out)
    history = []
    if os.path.exists(DISK_LOG):
        try:
            with open(DISK_LOG, encoding="utf-8") as f: history = json.load(f)
        except: pass
    history.append({"time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "data": out})
    history = history[-30:]
    with open(DISK_LOG, "w", encoding="utf-8") as f:
        json.dump(history, f, ensure_ascii=False, indent=2)
    print(f"\nĐã ghi nhận ({len(history)} lần).")

def backup_config():
    print_header("7. Backup cấu hình")
    import shutil
    backup_dir = Path("config_backup") / datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_dir.mkdir(parents=True, exist_ok=True)
    plat = get_platform()
    items = []
    if plat in ["linux", "darwin"]:
        home = Path.home()
        items = [home/".bashrc", home/".zshrc", home/".gitconfig", home/".ssh"]
    elif plat == "android":
        home = Path.home()
        items = [home/".bashrc", home/".termux"]
    for item in items:
        if item.exists():
            try:
                dest = backup_dir / item.name
                if item.is_dir():
                    shutil.copytree(item, dest, dirs_exist_ok=True)
                else:
                    shutil.copy2(item, dest)
                print(f"Đã backup: {item}")
            except Exception as e:
                print(f"Lỗi {item}: {e}")
    print(f"Lưu tại: {backup_dir}")

def battery_temp():
    print_header("8. Pin + nhiệt độ")
    if get_platform() == "android":
        print(run_cmd("dumpsys battery"))
    else:
        print(run_cmd("acpi -V 2>/dev/null") or "Tối ưu cho Android")

def arp_spoof_check():
    print_header("9. Phát hiện ARP Spoofing")
    print(run_cmd("arp -a" if get_platform()=="windows" else "ip neigh show || arp -a"))
    print("\nNếu MAC gateway thay đổi bất thường → nghi ngờ spoof.")

def dns_hijack_check():
    print_header("10. Kiểm tra DNS Hijacking")
    for domain in ["google.com", "facebook.com", "cloudflare.com"]:
        try:
            print(f"{domain}: {socket.gethostbyname(domain)}")
        except: pass
        out = run_cmd(f"nslookup {domain} 8.8.8.8")
        m = re.search(r"Address: (\d+\.\d+\.\d+\.\d+)", out)
        if m: print(f"  Google DNS: {m.group(1)}")
        print()

def network_log():
    print_header("11. Log kết nối mạng")
    if get_platform() == "windows":
        print(run_cmd("netstat -ano | findstr ESTABLISHED"))
    else:
        print(run_cmd("ss -tunap 2>/dev/null || netstat -tunap 2>/dev/null | head -n 35"))

def ssl_batch_check():
    print_header("12. Kiểm tra SSL hàng loạt")
    raw = input("Domain (cách nhau bởi dấu phẩy): ").strip()
    for domain in [d.strip() for d in raw.split(",") if d.strip()]:
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=7) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    print(f"{domain}: Hết hạn {cert.get('notAfter')}")
        except Exception as e:
            print(f"{domain}: Lỗi - {e}")

def domain_ip_email_info():
    print_header("13. Domain / IP / Email")
    target = input("Nhập domain / IP / email: ").strip()
    if not target: return
    if "@" in target:
        user, domain = target.split("@", 1)
        print(f"Username: {user}\nDomain: {domain}")
        print(run_cmd(f"nslookup -type=MX {domain}")[:400])
    else:
        try:
            ip = socket.gethostbyname(target)
            print(f"IP: {ip}")
            data = urllib.request.urlopen(f"http://ip-api.com/json/{ip}", timeout=8).read().decode()
            info = json.loads(data)
            print(f"Quốc gia : {info.get('country')}")
            print(f"Thành phố: {info.get('city')}")
            print(f"ISP      : {info.get('isp')}")
        except Exception as e: print(e)

def pwned_check():
    print_header("14. Kiểm tra Password bị lộ")
    pw = input("Mật khẩu: ").strip()
    if not pw: return
    sha1 = hashlib.sha1(pw.encode()).hexdigest().upper()
    try:
        req = urllib.request.Request(f"https://api.pwnedpasswords.com/range/{sha1[:5]}", headers={"User-Agent":"Toolkit"})
        with urllib.request.urlopen(req, timeout=10) as r:
            for line in r.read().decode().splitlines():
                if line.startswith(sha1[5:]):
                    print(f"[!] Đã bị lộ {line.split(':')[1]} lần!")
                    return
        print("[+] Không thấy bị lộ.")
    except Exception as e: print(e)

def exif_metadata():
    print_header("15. Metadata ảnh (EXIF)")
    try:
        from PIL import Image
        from PIL.ExifTags import TAGS
    except:
        print("Cần: pip install Pillow")
        return
    path = input("Đường dẫn ảnh: ").strip().strip('"')
    if not os.path.exists(path): return
    img = Image.open(path)
    print(f"Size: {img.size} | Format: {img.format}")
    exif = img._getexif()
    if not exif:
        print("Không có EXIF")
        return
    for k, v in exif.items():
        print(f"  {TAGS.get(k,k)}: {v}")

def _pm_load_or_init(master_pw, create_if_missing=True):
    """Trả về (entries_dict, salt). None, None nghĩa là sai master password."""
    if not os.path.exists(PASSWORD_DB):
        if not create_if_missing:
            return None, None
        return {}, os.urandom(16)
    with open(PASSWORD_DB, encoding="utf-8") as f:
        store = json.load(f)
    if "salt" not in store or "data" not in store:
        # File cũ dạng plaintext (từ bản trước khi mã hóa) -> tự di chuyển
        print("  [!] Phát hiện passwords.json ở định dạng CŨ (plaintext, chưa mã hóa).")
        print("      Sẽ tự động mã hóa lại bằng master password bạn vừa nhập.")
        return store, os.urandom(16)
    salt = base64.b64decode(store["salt"])
    key = derive_fernet_key(master_pw, salt)
    try:
        raw = Fernet(key).decrypt(store["data"].encode())
    except InvalidToken:
        return None, None
    return json.loads(raw.decode()), salt

def _pm_save(master_pw, entries, salt):
    key = derive_fernet_key(master_pw, salt)
    token = Fernet(key).encrypt(json.dumps(entries, ensure_ascii=False).encode())
    store = {"salt": base64.b64encode(salt).decode(), "data": token.decode()}
    with open(PASSWORD_DB, "w", encoding="utf-8") as f:
        json.dump(store, f, ensure_ascii=False, indent=2)

def password_manager():
    print_header("16. Tạo & quản lý mật khẩu (kho được mã hóa bằng master password)")
    print("1. Tạo mật khẩu mới (ngẫu nhiên)")
    print("2. Lưu mật khẩu (mã hóa)")
    print("3. Xem mật khẩu đã lưu (cần master password)")
    print("4. Đổi master password")
    c = input("Chọn: ").strip()

    if c == "1":
        length = input("Độ dài (16): ").strip()
        length = int(length) if length.isdigit() else 16
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        print("Mật khẩu:", "".join(secrets.choice(chars) for _ in range(length)))
        return

    if not CRYPTO_AVAILABLE:
        print("Cần cài thư viện: pip install cryptography")
        return

    if c == "2":
        service = input("Tên dịch vụ: ").strip()
        pwd = input("Mật khẩu: ").strip()
        if not service or not pwd:
            return
        master = input("Master password (dùng để mã hóa/mở kho mật khẩu): ").strip()
        if not master:
            print("Master password không được để trống")
            return
        entries, salt = _pm_load_or_init(master)
        if entries is None:
            print("❌ Sai master password (không khớp với kho hiện có).")
            return
        entries[service] = {"password": pwd, "time": datetime.now().strftime("%Y-%m-%d %H:%M")}
        _pm_save(master, entries, salt)
        print("Đã lưu (đã mã hóa).")

    elif c == "3":
        if not os.path.exists(PASSWORD_DB):
            print("Chưa có dữ liệu")
            return
        master = input("Master password: ").strip()
        entries, salt = _pm_load_or_init(master, create_if_missing=False)
        if entries is None:
            print("❌ Sai master password.")
            return
        if not entries:
            print("Chưa có mục nào.")
            return
        for k, v in entries.items():
            print(f"  {k}: {v['password']}  (lưu lúc {v.get('time', '?')})")

    elif c == "4":
        if not os.path.exists(PASSWORD_DB):
            print("Chưa có dữ liệu để đổi master password.")
            return
        old = input("Master password hiện tại: ").strip()
        entries, _ = _pm_load_or_init(old, create_if_missing=False)
        if entries is None:
            print("❌ Sai master password.")
            return
        new = input("Master password mới: ").strip()
        if not new:
            print("Không được để trống")
            return
        _pm_save(new, entries, os.urandom(16))
        print("✅ Đã đổi master password thành công.")
    else:
        print("Lựa chọn không hợp lệ")

def file_encrypt_decrypt():
    # ĐÃ NÂNG CẤP: trước đây dùng XOR (rất yếu, dễ bị bẻ khóa nếu biết trước
    # một phần nội dung file gốc). Giờ dùng AES qua Fernet + PBKDF2 (200,000
    # vòng lặp) để dẫn xuất khóa từ mật khẩu — chuẩn công nghiệp.
    if not CRYPTO_AVAILABLE:
        print("Cần cài thư viện: pip install cryptography")
        return

    MAGIC = b"ENCV3\x00"
    SALT_LEN = 16

    print_header("17. Mã hóa / Giải mã File hoặc Thư mục (AES/Fernet)")
    print("1. Mã hóa (File hoặc Thư mục)")
    print("2. Giải mã (File hoặc Thư mục)")
    choice = input("Chọn: ").strip()

    path = input("Đường dẫn file/thư mục: ").strip().strip('"')
    if not os.path.exists(path):
        print("Đường dẫn không tồn tại")
        return

    key = input("Key (mật khẩu, nên dài & khó đoán): ").strip()
    if not key:
        print("Key không được để trống")
        return

    def encrypt_single_file(file_path):
        if file_path.endswith(".enc"):
            return False
        try:
            with open(file_path, "rb") as f:
                data = f.read()
            salt = os.urandom(SALT_LEN)
            fkey = derive_fernet_key(key, salt)
            token = Fernet(fkey).encrypt(data)
            out_path = file_path + ".enc"
            with open(out_path, "wb") as f:
                f.write(MAGIC + salt + token)
            return True
        except Exception as e:
            print(f"❌ Lỗi mã hóa {file_path}: {e}")
            return False

    def decrypt_single_file(file_path):
        if not file_path.endswith(".enc"):
            return False
        try:
            with open(file_path, "rb") as f:
                raw = f.read()
            if raw[:len(MAGIC)] != MAGIC:
                print(f"❌ File không đúng định dạng ENCV3: {file_path}")
                return False
            salt = raw[len(MAGIC):len(MAGIC) + SALT_LEN]
            token = raw[len(MAGIC) + SALT_LEN:]
            fkey = derive_fernet_key(key, salt)
            try:
                content = Fernet(fkey).decrypt(token)
            except InvalidToken:
                print(f"❌ Sai Key đối với file: {file_path}")
                return False
            out_path = file_path[:-4]
            with open(out_path, "wb") as f:
                f.write(content)
            return True
        except Exception as e:
            print(f"❌ Lỗi giải mã {file_path}: {e}")
            return False

    if choice == "1":
        files_to_process = []
        if os.path.isfile(path):
            files_to_process.append(path)
        else:
            for root, _, files in os.walk(path):
                for file in files:
                    if not file.endswith(".enc"):
                        files_to_process.append(os.path.join(root, file))

        if not files_to_process:
            print("Không tìm thấy file hợp lệ để mã hóa.")
            return

        success_count = 0
        for f_path in files_to_process:
            if encrypt_single_file(f_path):
                success_count += 1

        print(f"\n✅ Đã mã hóa {success_count}/{len(files_to_process)} file.")

        confirm = input("Xóa các file gốc? (y/n): ").strip().lower()
        if confirm == "y":
            deleted = 0
            for f_path in files_to_process:
                if os.path.exists(f_path + ".enc"):
                    try:
                        os.remove(f_path)
                        deleted += 1
                    except:
                        pass
            print(f"Đã xóa {deleted} file gốc.")

    elif choice == "2":
        files_to_process = []
        if os.path.isfile(path):
            files_to_process.append(path)
        else:
            for root, _, files in os.walk(path):
                for file in files:
                    if file.endswith(".enc"):
                        files_to_process.append(os.path.join(root, file))

        if not files_to_process:
            print("Không tìm thấy file .enc nào để giải mã.")
            return

        success_count = 0
        for f_path in files_to_process:
            if decrypt_single_file(f_path):
                success_count += 1

        print(f"\n✅ Đã giải mã thành công {success_count}/{len(files_to_process)} file.")

        confirm = input("Xóa các file .enc? (y/n): ").strip().lower()
        if confirm == "y":
            deleted = 0
            for f_path in files_to_process:
                if os.path.exists(f_path[:-4]):
                    try:
                        os.remove(f_path)
                        deleted += 1
                    except:
                        pass
            print(f"Đã xóa {deleted} file .enc.")
    else:
        print("Lựa chọn không hợp lệ")

def secure_notes():
    print_header("18. Ghi chú bảo mật (mã hóa AES)")
    if not CRYPTO_AVAILABLE:
        print("Cần cài thư viện: pip install cryptography")
        return
    print("1. Thêm ghi chú")
    print("2. Xem ghi chú")
    c = input("Chọn: ").strip()
    if c == "1":
        note = input("Nội dung: ").strip()
        pw = input("Mật khẩu bảo vệ: ").strip()
        if not note or not pw: return
        salt = os.urandom(16)
        key = derive_fernet_key(pw, salt)
        token = Fernet(key).encrypt(note.encode())
        notes = []
        if os.path.exists(NOTES_FILE):
            with open(NOTES_FILE, encoding="utf-8") as f: notes = json.load(f)
        notes.append({
            "time": datetime.now().strftime("%Y-%m-%d %H:%M"),
            "salt": base64.b64encode(salt).decode(),
            "data": token.decode(),
        })
        with open(NOTES_FILE, "w", encoding="utf-8") as f:
            json.dump(notes, f, ensure_ascii=False, indent=2)
        print("Đã lưu.")
    elif c == "2":
        if not os.path.exists(NOTES_FILE):
            print("Chưa có ghi chú"); return
        pw = input("Mật khẩu: ").strip()
        with open(NOTES_FILE, encoding="utf-8") as f: notes = json.load(f)
        for n in notes:
            if "salt" not in n:
                print(f"[{n['time']}] → Ghi chú định dạng cũ (XOR), bản mới không đọc được.")
                continue
            try:
                salt = base64.b64decode(n["salt"])
                key = derive_fernet_key(pw, salt)
                content = Fernet(key).decrypt(n["data"].encode()).decode()
                print(f"[{n['time']}] {content}")
            except InvalidToken:
                print(f"[{n['time']}] → Sai mật khẩu")

def file_integrity_monitor():
    print_header("19. File Integrity Monitor (giám sát thay đổi file)")
    print("1. Tạo baseline (chụp hash hiện tại của thư mục)")
    print("2. Kiểm tra thay đổi so với baseline")
    c = input("Chọn: ").strip()

    baseline = {}
    if os.path.exists(INTEGRITY_DB):
        try:
            with open(INTEGRITY_DB, encoding="utf-8") as f:
                baseline = json.load(f)
        except Exception:
            baseline = {}

    if c == "1":
        path = input("Đường dẫn thư mục cần giám sát: ").strip().strip('"')
        if not os.path.isdir(path):
            print("Thư mục không tồn tại")
            return
        snapshot = {}
        count = 0
        for root, _, files in os.walk(path):
            for name in files:
                full = os.path.join(root, name)
                _, sha = calc_hash(full)
                if sha:
                    snapshot[full] = sha
                    count += 1
        baseline[os.path.abspath(path)] = snapshot
        with open(INTEGRITY_DB, "w", encoding="utf-8") as f:
            json.dump(baseline, f, ensure_ascii=False, indent=2)
        print(f"Đã lưu baseline: {count} file trong '{path}'.")

    elif c == "2":
        if not baseline:
            print("Chưa có baseline nào. Hãy tạo baseline trước (mục 1).")
            return
        print("Các thư mục đã có baseline:")
        paths = list(baseline.keys())
        for i, p in enumerate(paths, 1):
            print(f"  {i}. {p}")
        idx = input("Chọn số thứ tự: ").strip()
        if not idx.isdigit() or not (1 <= int(idx) <= len(paths)):
            print("Lựa chọn không hợp lệ")
            return
        target = paths[int(idx) - 1]
        old_snapshot = baseline[target]

        new_snapshot = {}
        for root, _, files in os.walk(target):
            for name in files:
                full = os.path.join(root, name)
                _, sha = calc_hash(full)
                if sha:
                    new_snapshot[full] = sha

        added = [f for f in new_snapshot if f not in old_snapshot]
        removed = [f for f in old_snapshot if f not in new_snapshot]
        modified = [f for f in new_snapshot if f in old_snapshot and new_snapshot[f] != old_snapshot[f]]

        if not added and not removed and not modified:
            print("✅ Không phát hiện thay đổi nào.")
        else:
            if modified:
                print(f"\n⚠️  File BỊ SỬA ĐỔI ({len(modified)}):")
                for f in modified: print(f"  {f}")
            if added:
                print(f"\n➕ File MỚI ({len(added)}):")
                for f in added: print(f"  {f}")
            if removed:
                print(f"\n➖ File BỊ XÓA ({len(removed)}):")
                for f in removed: print(f"  {f}")
        upd = input("\nCập nhật baseline thành trạng thái hiện tại? (y/n): ").strip().lower()
        if upd == "y":
            baseline[target] = new_snapshot
            with open(INTEGRITY_DB, "w", encoding="utf-8") as f:
                json.dump(baseline, f, ensure_ascii=False, indent=2)
            print("Đã cập nhật baseline.")
    else:
        print("Lựa chọn không hợp lệ")

def check_open_ports():
    print_header("20. Kiểm tra cổng đang mở / lắng nghe")
    plat = get_platform()
    if plat == "windows":
        out = run_cmd("netstat -ano | findstr LISTENING")
    elif plat == "android":
        out = run_cmd("netstat -tulpn 2>/dev/null") or run_cmd("ss -tulpn 2>/dev/null")
    else:
        out = run_cmd("ss -tulpn 2>/dev/null") or run_cmd("netstat -tulpn 2>/dev/null")
    if not out:
        print("Không lấy được danh sách cổng (có thể cần quyền root/admin).")
        return
    print(out)

    common_safe = {20, 21, 22, 23, 25, 53, 67, 68, 80, 110, 123, 143, 443, 445, 3306, 3389, 5432, 5900, 8080}
    found_ports = set(int(p) for p in re.findall(r"[:.](\d{2,5})\s", out))
    unusual = sorted(p for p in found_ports if p not in common_safe and p > 1024)
    if unusual:
        print(f"\n⚠️  Các cổng lạ (không phổ biến) đang mở, nên kiểm tra kỹ: {unusual}")
    print("\nGợi ý: cổng lạ đang LISTEN có thể là backdoor/mã độc — tra chéo với mục 2 (Process) để xem tiến trình nào đang mở cổng đó.")

def url_reputation_check():
    print_header("21. Kiểm tra URL / Link đáng ngờ (Phishing)")
    api_key = get_vt_api_key()
    if not api_key:
        print("Cần API Key VirusTotal cho tính năng này.")
        return
    url = input("Nhập URL cần kiểm tra: ").strip()
    if not url:
        return
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        req = urllib.request.Request(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": api_key},
        )
        try:
            with urllib.request.urlopen(req, timeout=12) as resp:
                data = json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            if e.code == 404:
                # URL chưa từng được submit -> gửi lên để phân tích
                print("  URL chưa có trong dữ liệu VirusTotal, đang gửi để quét...")
                submit_req = urllib.request.Request(
                    "https://www.virustotal.com/api/v3/urls",
                    data=f"url={urllib.parse.quote(url)}".encode(),
                    headers={"x-apikey": api_key, "Content-Type": "application/x-www-form-urlencoded"},
                )
                with urllib.request.urlopen(submit_req, timeout=12) as sresp:
                    json.loads(sresp.read().decode())
                print("  Đã gửi. VirusTotal cần vài chục giây để phân tích, hãy thử lại sau ít phút.")
                return
            raise
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        print(f"  Malicious: {malicious} | Suspicious: {suspicious} | Harmless: {stats.get('harmless', 0)}")
        if malicious > 0:
            print(f"  🚨 CẢNH BÁO: {malicious} engine đánh dấu URL này là ĐỘC HẠI. KHÔNG nên truy cập!")
        elif suspicious > 0:
            print("  ⚠️  Có dấu hiệu đáng ngờ, nên thận trọng.")
        else:
            print("  ✅ Chưa phát hiện dấu hiệu độc hại.")
    except Exception as e:
        print(f"Lỗi: {e}")

def totp_generator():
    import hmac, struct

    def make_secret():
        return base64.b32encode(os.urandom(10)).decode().rstrip("=")

    def totp_code(secret_b32: str, for_time=None, digits=6, period=30):
        secret_b32 = secret_b32.strip().upper().replace(" ", "")
        pad = "=" * ((8 - len(secret_b32) % 8) % 8)
        key = base64.b32decode(secret_b32 + pad)
        t = int((for_time or time.time()) // period)
        msg = struct.pack(">Q", t)
        h = hmac.new(key, msg, hashlib.sha1).digest()
        offset = h[-1] & 0x0F
        code_int = (struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
        return str(code_int).zfill(digits), period - int(time.time()) % period

    print_header("22. Trình tạo mã 2FA/TOTP (Google Authenticator-compatible)")
    print("1. Tạo secret mới cho một tài khoản")
    print("2. Nhập secret có sẵn để lấy mã hiện tại")
    c = input("Chọn: ").strip()

    if c == "1":
        service = input("Tên dịch vụ (vd: Gmail): ").strip() or "unknown"
        secret = make_secret()
        print(f"\nSecret (lưu lại để dùng cho lần sau, hoặc nhập vào app Authenticator): {secret}")
        code, remain = totp_code(secret)
        print(f"Mã hiện tại: {code} (còn hiệu lực {remain}s)")
        save = input("Lưu secret này vào password manager (mục 16)? (y/n): ").strip().lower()
        if save == "y":
            data = {}
            if os.path.exists(PASSWORD_DB):
                with open(PASSWORD_DB, encoding="utf-8") as f:
                    data = json.load(f)
            data[f"{service} (TOTP secret)"] = {"password": secret, "time": datetime.now().strftime("%Y-%m-%d %H:%M")}
            with open(PASSWORD_DB, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            print("Đã lưu.")
    elif c == "2":
        secret = input("Nhập secret (base32): ").strip()
        if not secret:
            return
        try:
            code, remain = totp_code(secret)
            print(f"Mã hiện tại: {code} (còn hiệu lực {remain}s)")
        except Exception as e:
            print(f"Secret không hợp lệ: {e}")
    else:
        print("Lựa chọn không hợp lệ")

def failed_login_analysis():
    print_header("23. Phân tích đăng nhập thất bại (phát hiện brute-force)")
    plat = get_platform()
    if plat == "windows":
        print("Đang truy vấn Security Event Log (Event ID 4625 = đăng nhập thất bại)...")
        print("Lưu ý: cần chạy với quyền Administrator.")
        out = run_cmd('wevtutil qe Security /q:"*[System[(EventID=4625)]]" /c:20 /rd:true /f:text', timeout=20)
        if not out:
            print("Không lấy được log (thiếu quyền admin hoặc không có sự kiện nào).")
            return
        print(out[:4000])
    else:
        log_candidates = ["/var/log/auth.log", "/var/log/secure"]
        log_path = next((p for p in log_candidates if os.path.exists(p)), None)
        if not log_path:
            print("Không tìm thấy file log đăng nhập (cần quyền đọc /var/log/auth.log hoặc /var/log/secure).")
            print("Trên Android/Termux tính năng này thường không khả dụng.")
            return
        out = run_cmd(f"grep 'Failed password' {log_path} | tail -n 200", timeout=15)
        if not out:
            print("Không tìm thấy dòng log đăng nhập thất bại nào (hoặc thiếu quyền đọc).")
            return
        ip_counts = {}
        for line in out.splitlines():
            m = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
            if m:
                ip_counts[m.group(1)] = ip_counts.get(m.group(1), 0) + 1
        if not ip_counts:
            print(out[-2000:])
            return
        print("Số lần đăng nhập thất bại theo IP (200 dòng log gần nhất):")
        for ip, cnt in sorted(ip_counts.items(), key=lambda x: -x[1]):
            flag = "  🚨 NGHI VẤN BRUTE-FORCE" if cnt >= 5 else ""
            print(f"  {ip}: {cnt} lần{flag}")

def check_sensitive_permissions():
    print_header("24. Kiểm tra quyền file/thư mục nhạy cảm")
    plat = get_platform()
    if plat == "windows":
        print("Trên Windows, quyền truy cập dùng ACL riêng, không dùng chmod-style bits.")
        print("Gợi ý: chạy 'icacls <đường_dẫn>' để xem ACL của file/thư mục quan trọng.")
        return

    import stat
    home = Path.home()
    targets = [
        home / ".ssh",
        home / ".ssh" / "id_rsa",
        home / ".ssh" / "id_ed25519",
        home / ".gitconfig",
        home / ".aws" / "credentials",
        home / ".env",
        Path.cwd() / PASSWORD_DB,
        Path.cwd() / CONFIG_FILE,
    ]
    found_any = False
    for t in targets:
        if not t.exists():
            continue
        found_any = True
        mode = t.stat().st_mode
        perms = stat.filemode(mode)
        world_readable = bool(mode & stat.S_IROTH)
        world_writable = bool(mode & stat.S_IWOTH)
        group_writable = bool(mode & stat.S_IWGRP)
        warn = ""
        if world_writable:
            warn = "  🚨 NGUY HIỂM: mọi người đều có thể GHI file này!"
        elif world_readable:
            warn = "  ⚠️  Cảnh báo: mọi người đều có thể ĐỌC file nhạy cảm này."
        elif group_writable:
            warn = "  ⚠️  Nhóm (group) có quyền ghi — nên kiểm tra lại."
        print(f"  {t}  [{perms}]{warn}")
        if warn:
            print(f"    → Sửa bằng: chmod 600 \"{t}\"" if t.is_file() else f"    → Sửa bằng: chmod 700 \"{t}\"")
    if not found_any:
        print("Không tìm thấy file/thư mục nhạy cảm phổ biến nào trên máy này.")

def usb_watch():
    print_header("25. Cảnh báo khi có USB/ổ đĩa mới cắm vào")
    plat = get_platform()

    def list_drives():
        if plat == "windows":
            out = run_cmd("wmic logicaldisk get caption")
            return set(l.strip() for l in out.splitlines() if l.strip() and l.strip() != "Caption")
        else:
            out = run_cmd("lsblk -o NAME,MOUNTPOINT -P 2>/dev/null") or run_cmd("cat /proc/mounts")
            return set(out.splitlines())

    print("Đang theo dõi... (Ctrl+C để dừng)")
    known = list_drives()
    try:
        while True:
            time.sleep(3)
            current = list_drives()
            new_items = current - known
            if new_items:
                print(f"\n🔌 Phát hiện thiết bị/ổ đĩa MỚI lúc {datetime.now().strftime('%H:%M:%S')}:")
                for item in new_items:
                    print(f"   {item}")
                print("   → Gợi ý: chạy mục 4 (Quét USB/ổ cứng) để kiểm tra file đáng ngờ trên ổ này.")
                known = current
            else:
                known = current
    except KeyboardInterrupt:
        print("\nĐã dừng theo dõi.")

def check_firewall_status():
    print_header("26. Kiểm tra trạng thái Tường lửa (Firewall)")
    plat = get_platform()
    if plat == "windows":
        out = run_cmd("netsh advfirewall show allprofiles state")
        print(out or "Không lấy được trạng thái (thử chạy với quyền Administrator).")
        if out and "OFF" in out.upper():
            print("\n⚠️  Có ít nhất một profile firewall đang TẮT.")
    elif plat == "linux":
        out = run_cmd("ufw status verbose 2>/dev/null")
        if out:
            print(out)
            if "inactive" in out.lower():
                print("\n⚠️  UFW đang TẮT — máy không được bảo vệ bởi firewall (ufw).")
        else:
            out2 = run_cmd("iptables -L -n 2>/dev/null")
            print(out2 or "Không tìm thấy ufw, hoặc thiếu quyền để kiểm tra (thử chạy với sudo).")
    elif plat == "darwin":
        out = run_cmd("/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate")
        print(out or "Không lấy được trạng thái tường lửa macOS.")
    else:
        print("Chưa hỗ trợ kiểm tra firewall trên nền tảng này (Android không có khái niệm này theo cách tương tự).")

def secure_delete():
    print_header("27. Xóa file an toàn (Secure Delete / Shred)")
    print("⚠️  File sẽ bị GHI ĐÈ NHIỀU LẦN rồi xóa vĩnh viễn — KHÔNG THỂ khôi phục!")
    path = input("Đường dẫn file cần xóa vĩnh viễn: ").strip().strip('"')
    if not os.path.isfile(path):
        print("File không tồn tại (chỉ hỗ trợ xóa từng file, không phải cả thư mục).")
        return
    confirm = input(f"Gõ chính xác XOA để xác nhận xóa vĩnh viễn '{path}': ").strip()
    if confirm != "XOA":
        print("Đã hủy — không có gì bị xóa.")
        return
    try:
        size = os.path.getsize(path)
        passes = 3
        with open(path, "r+b") as f:
            for _ in range(passes):
                f.seek(0)
                f.write(os.urandom(size))
                f.flush()
                os.fsync(f.fileno())
        os.remove(path)
        print(f"✅ Đã ghi đè {passes} lần bằng dữ liệu ngẫu nhiên rồi xóa vĩnh viễn: {path}")
        print("Lưu ý: trên ổ SSD (do cơ chế wear-leveling), không có phương pháp phần mềm nào")
        print("đảm bảo xóa dữ liệu 100% — để chắc chắn tuyệt đối, hãy dùng mã hóa toàn ổ đĩa")
        print("(BitLocker trên Windows, LUKS trên Linux) ngay từ đầu.")
    except Exception as e:
        print(f"Lỗi: {e}")

def wifi_password_audit():
    print_header("28. Kiểm tra mật khẩu WiFi đã lưu trên máy này")
    print("(Chỉ hiển thị mật khẩu WiFi mà CHÍNH máy này đã lưu — dùng để tự kiểm tra/sao lưu.)\n")
    plat = get_platform()
    if plat == "windows":
        profiles_out = run_cmd("netsh wlan show profiles")
        names = re.findall(r"All User Profile\s*:\s*(.+)", profiles_out)
        if not names:
            print("Không tìm thấy profile WiFi nào (hoặc cần chạy với quyền Admin).")
            return
        for name in names:
            name = name.strip()
            detail = run_cmd(f'netsh wlan show profile name="{name}" key=clear')
            m = re.search(r"Key Content\s*:\s*(.+)", detail)
            pwd = m.group(1).strip() if m else "(không có mật khẩu / mạng mở)"
            print(f"  {name}: {pwd}")
    elif plat == "linux":
        conn_dir = "/etc/NetworkManager/system-connections"
        if os.path.isdir(conn_dir):
            out = run_cmd(f"grep -r 'psk=' {conn_dir} 2>/dev/null")
            print(out if out else "Không đọc được (cần quyền root — thử chạy: sudo python3 <script>.py).")
        else:
            print("Không tìm thấy thư mục cấu hình NetworkManager trên máy này.")
    else:
        print("Chưa hỗ trợ nền tảng này — macOS/Android cần công cụ riêng của hệ điều hành.")

def ssh_hardening_check():
    print_header("29. Kiểm tra cấu hình SSH (SSH Hardening Check)")
    if get_platform() == "windows":
        print("Windows không chạy sshd theo cách mặc định — bỏ qua kiểm tra này.")
        return
    path = "/etc/ssh/sshd_config"
    if not os.path.exists(path):
        print("Không tìm thấy /etc/ssh/sshd_config trên máy này (có thể không chạy SSH server).")
        return
    content = run_cmd(f"cat {path} 2>/dev/null") or ""
    if not content:
        print("Không đọc được file (có thể cần quyền root — thử chạy: sudo python3 <script>.py).")
        return

    checks = [
        ("PermitRootLogin", "yes", "🚨 Cho phép đăng nhập root trực tiếp qua SSH — nên đặt 'no' hoặc 'prohibit-password'."),
        ("PasswordAuthentication", "yes", "⚠️  Cho phép đăng nhập bằng mật khẩu (dễ bị brute-force) — nên chuyển sang SSH key và đặt 'no'."),
        ("PermitEmptyPasswords", "yes", "🚨 Cho phép mật khẩu RỖNG — cực kỳ nguy hiểm, phải sửa ngay thành 'no'."),
        ("X11Forwarding", "yes", "ℹ️  X11Forwarding đang bật — nên tắt nếu không thực sự cần dùng."),
    ]
    found_issue = False
    for key, bad_value, msg in checks:
        m = re.search(rf"^\s*{key}\s+(\S+)", content, re.MULTILINE | re.IGNORECASE)
        if m and m.group(1).lower() == bad_value:
            print(f"  {msg}")
            found_issue = True

    port_m = re.search(r"^\s*Port\s+(\d+)", content, re.MULTILINE)
    print(f"\n  Cổng SSH đang dùng: {port_m.group(1) if port_m else '22 (mặc định)'}")
    if not found_issue:
        print("  ✅ Không phát hiện cấu hình rủi ro rõ ràng trong các mục kiểm tra cơ bản.")

def security_report():
    print_header("30. Báo cáo tổng hợp bảo mật nhanh")
    print("Đang chạy các kiểm tra nhanh...\n")
    issues = []
    plat = get_platform()

    if plat == "linux":
        out = run_cmd("ufw status 2>/dev/null")
        if out and "inactive" in out.lower():
            issues.append("Firewall (ufw) đang TẮT.")
    elif plat == "windows":
        out = run_cmd("netsh advfirewall show allprofiles state")
        if out and "OFF" in out.upper():
            issues.append("Một hoặc nhiều Firewall profile đang TẮT.")

    if plat == "windows":
        pout = run_cmd("netstat -ano | findstr LISTENING")
    else:
        pout = run_cmd("ss -tulpn 2>/dev/null") or run_cmd("netstat -tulpn 2>/dev/null")
    common_safe = {20,21,22,23,25,53,67,68,80,110,123,143,443,445,3306,3389,5432,5900,8080}
    found_ports = set(int(p) for p in re.findall(r"[:.](\d{2,5})\s", pout or ""))
    unusual = sorted(p for p in found_ports if p not in common_safe and p > 1024)
    if unusual:
        issues.append(f"Có {len(unusual)} cổng lạ đang mở: {unusual}")

    if plat != "windows" and os.path.exists("/etc/ssh/sshd_config"):
        content = run_cmd("cat /etc/ssh/sshd_config 2>/dev/null") or ""
        if re.search(r"^\s*PermitRootLogin\s+yes", content, re.MULTILINE | re.IGNORECASE):
            issues.append("SSH cho phép đăng nhập root trực tiếp (PermitRootLogin yes).")
        if re.search(r"^\s*PermitEmptyPasswords\s+yes", content, re.MULTILINE | re.IGNORECASE):
            issues.append("SSH cho phép mật khẩu rỗng (PermitEmptyPasswords yes).")

    if plat != "windows":
        import stat
        home = Path.home()
        for t in [home/".ssh", home/".ssh"/"id_rsa"]:
            if t.exists():
                mode = t.stat().st_mode
                if mode & stat.S_IROTH:
                    issues.append(f"{t} có thể bị đọc bởi người dùng khác (world-readable).")

    if not issues:
        print("✅ Không phát hiện vấn đề nghiêm trọng nào qua các kiểm tra nhanh.")
        print("   (Đây chỉ là kiểm tra sơ bộ, không thay thế audit bảo mật đầy đủ.)")
    else:
        print(f"Phát hiện {len(issues)} vấn đề cần chú ý:\n")
        for i, msg in enumerate(issues, 1):
            print(f"  {i}. {msg}")
        print("\nGợi ý: xem chi tiết & khắc phục qua mục 20 (cổng), 24 (quyền file), 26 (firewall), 29 (SSH).")

def main():
    while True:
        print("\n" + "="*55)
        print("     FULL TOOLKIT + VirusTotal")
        print("="*55)
        print("--- Bảo mật & Kiểm tra ---")
        print("1. Hash hàng loạt + VirusTotal")
        print("2. Theo dõi Process")
        print("3. Kiểm tra Startup")
        print("4. Quét USB/ổ cứng")
        print()
        print("--- Hệ thống ---")
        print("5. Dọn rác")
        print("6. Theo dõi dung lượng ổ đĩa")
        print("7. Backup cấu hình")
        print("8. Pin + nhiệt độ")
        print()
        print("--- Mạng nâng cao ---")
        print("9. Phát hiện ARP Spoofing")
        print("10. Kiểm tra DNS Hijacking")
        print("11. Log kết nối mạng")
        print("12. Kiểm tra SSL hàng loạt")
        print()
        print("--- OSINT ---")
        print("13. Domain / IP / Email")
        print("14. Kiểm tra Password bị lộ")
        print("15. Metadata ảnh (EXIF)")
        print()
        print("--- Tiện ích ---")
        print("16. Tạo & quản lý mật khẩu")
        print("17. Mã hóa / Giải mã file hoặc thư mục (AES)")
        print("18. Ghi chú bảo mật")
        print()
        print("--- Bảo mật nâng cao ---")
        print("19. File Integrity Monitor")
        print("20. Kiểm tra cổng đang mở/lắng nghe")
        print("21. Kiểm tra URL/Link đáng ngờ (Phishing)")
        print("22. Trình tạo mã 2FA/TOTP")
        print("23. Phân tích đăng nhập thất bại")
        print("24. Kiểm tra quyền file nhạy cảm")
        print("25. Cảnh báo USB/ổ đĩa mới cắm vào")
        print()
        print("--- Audit & Báo cáo ---")
        print("26. Kiểm tra trạng thái Tường lửa")
        print("27. Xóa file an toàn (Secure Delete)")
        print("28. Kiểm tra mật khẩu WiFi đã lưu")
        print("29. Kiểm tra cấu hình SSH")
        print("30. Báo cáo tổng hợp bảo mật nhanh")
        print()
        print("0. Thoát")
        print("="*55)

        c = input("Chọn: ").strip()
        if c=="1": batch_hash_vt()
        elif c=="2": monitor_process()
        elif c=="3": check_startup()
        elif c=="4": scan_usb_suspicious()
        elif c=="5": clean_junk()
        elif c=="6": disk_monitor()
        elif c=="7": backup_config()
        elif c=="8": battery_temp()
        elif c=="9": arp_spoof_check()
        elif c=="10": dns_hijack_check()
        elif c=="11": network_log()
        elif c=="12": ssl_batch_check()
        elif c=="13": domain_ip_email_info()
        elif c=="14": pwned_check()
        elif c=="15": exif_metadata()
        elif c=="16": password_manager()
        elif c=="17": file_encrypt_decrypt()
        elif c=="18": secure_notes()
        elif c=="19": file_integrity_monitor()
        elif c=="20": check_open_ports()
        elif c=="21": url_reputation_check()
        elif c=="22": totp_generator()
        elif c=="23": failed_login_analysis()
        elif c=="24": check_sensitive_permissions()
        elif c=="25": usb_watch()
        elif c=="26": check_firewall_status()
        elif c=="27": secure_delete()
        elif c=="28": wifi_password_audit()
        elif c=="29": ssh_hardening_check()
        elif c=="30": security_report()
        elif c=="0": break
        else: print("Không hợp lệ")
        input("\nNhấn Enter để tiếp tục...")

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: print("\nĐã dừng.")