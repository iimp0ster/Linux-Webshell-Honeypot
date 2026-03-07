<?php
session_start();

// Auth gate — unauthenticated visitors go back to login
if (!isset($_SESSION['oc_auth']) || $_SESSION['oc_auth'] !== true) {
    header('Location: index.php');
    exit;
}

// Logout
if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: index.php');
    exit;
}

$oc_user = $_SESSION['oc_user'] ?? 'admin';

// Captured files storage — intentionally outside the webroot so they cannot execute
define('CAPTURE_DIR', '/var/log/honeypot/captured_files');
define('LOG_FILE',    '/var/log/honeypot/uploads.log');

// Resolve real attacker IP
function resolve_ip(): string {
    $xff = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? null;
    if ($xff) {
        $ips = array_map('trim', explode(',', $xff));
        return $ips[0];
    }
    return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
}

$upload_toast = '';
$upload_error = '';

// Handle file upload
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    if (!file_exists(CAPTURE_DIR)) {
        mkdir(CAPTURE_DIR, 0755, true);
    }
    if (!file_exists(dirname(LOG_FILE))) {
        mkdir(dirname(LOG_FILE), 0755, true);
    }

    $xff = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? null;
    $log_entry = json_encode([
        'timestamp'       => gmdate('Y-m-d\TH:i:s\Z'),
        'filename'        => $_FILES['file']['name'],
        'size'            => (int)$_FILES['file']['size'],
        'reported_type'   => $_FILES['file']['type'],
        'ip'              => resolve_ip(),
        'x_forwarded_for' => $xff,
        'user_agent'      => $_SERVER['HTTP_USER_AGENT'] ?? '',
        'referer'         => $_SERVER['HTTP_REFERER'] ?? '',
        'accept_language' => $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '',
        'method'          => $_SERVER['REQUEST_METHOD'],
        'request_uri'     => $_SERVER['REQUEST_URI'] ?? '',
    ], JSON_UNESCAPED_SLASHES) . "\n";
    file_put_contents(LOG_FILE, $log_entry, FILE_APPEND | LOCK_EX);

    $dest = CAPTURE_DIR . '/' . basename($_FILES['file']['name']);
    if (move_uploaded_file($_FILES['file']['tmp_name'], $dest)) {
        $upload_toast = htmlspecialchars(basename($_FILES['file']['name']), ENT_QUOTES, 'UTF-8');
    } else {
        $upload_error = 'Upload failed. Please try again.';
    }
}

// Load captured files for display
$captured_files = [];
if (is_dir(CAPTURE_DIR)) {
    foreach (array_diff(scandir(CAPTURE_DIR), ['.', '..']) as $f) {
        $fp = CAPTURE_DIR . '/' . $f;
        if (is_file($fp)) {
            $captured_files[] = [
                'name'    => $f,
                'size'    => filesize($fp),
                'mtime'   => filemtime($fp),
            ];
        }
    }
}

// Fake pre-existing files that make the account look lived-in
$fake_files = [
    ['name' => 'Documents',          'size' => null,    'mtime' => strtotime('2025-10-14'), 'type' => 'folder'],
    ['name' => 'Photos',             'size' => null,    'mtime' => strtotime('2025-11-02'), 'type' => 'folder'],
    ['name' => 'Getting started.pdf','size' => 3621940, 'mtime' => strtotime('2025-09-01'), 'type' => 'pdf'],
];

function fmt_size(?int $bytes): string {
    if ($bytes === null) return '–';
    if ($bytes < 1024) return $bytes . ' B';
    if ($bytes < 1048576) return round($bytes / 1024, 1) . ' KB';
    return round($bytes / 1048576, 1) . ' MB';
}

function fmt_date(int $ts): string {
    return date('M j, Y', $ts);
}

function file_icon(string $name): string {
    $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
    $icons = [
        'pdf'  => '📄',
        'php'  => '📝',
        'js'   => '📝',
        'py'   => '📝',
        'sh'   => '📝',
        'txt'  => '📝',
        'zip'  => '🗜️',
        'tar'  => '🗜️',
        'gz'   => '🗜️',
        'jpg'  => '🖼️',
        'jpeg' => '🖼️',
        'png'  => '🖼️',
        'gif'  => '🖼️',
    ];
    return $icons[$ext] ?? '📄';
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Files – ownCloud</title>
    <style>
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            font-family: 'Open Sans', Arial, sans-serif;
            font-size: 14px;
            background: #f4f4f4;
            color: #333;
            min-height: 100vh;
        }

        /* ── Top Navigation Bar ── */
        #header {
            background: #0082c9;
            height: 50px;
            display: flex;
            align-items: center;
            padding: 0 16px;
            gap: 20px;
            position: fixed;
            top: 0; left: 0; right: 0;
            z-index: 100;
            box-shadow: 0 1px 4px rgba(0,0,0,0.3);
        }

        .header-logo {
            display: flex;
            align-items: center;
            gap: 8px;
            color: #fff;
            font-size: 18px;
            font-weight: 300;
            text-decoration: none;
            letter-spacing: -0.3px;
        }

        .header-logo svg { width: 28px; height: 28px; }

        .header-nav {
            display: flex;
            gap: 2px;
            flex: 1;
        }

        .header-nav a {
            color: rgba(255,255,255,0.75);
            text-decoration: none;
            padding: 6px 14px;
            border-radius: 3px;
            font-size: 13px;
            transition: color 0.15s, background 0.15s;
        }

        .header-nav a:hover,
        .header-nav a.active {
            color: #fff;
            background: rgba(255,255,255,0.15);
        }

        .header-right {
            display: flex;
            align-items: center;
            gap: 10px;
            color: #fff;
        }

        .search-icon { font-size: 18px; cursor: pointer; opacity: 0.8; }

        .user-menu {
            display: flex;
            align-items: center;
            gap: 7px;
            cursor: pointer;
            padding: 4px 10px;
            border-radius: 3px;
            transition: background 0.15s;
            position: relative;
        }

        .user-menu:hover { background: rgba(255,255,255,0.15); }

        .avatar {
            width: 30px; height: 30px;
            border-radius: 50%;
            background: rgba(255,255,255,0.25);
            display: flex; align-items: center; justify-content: center;
            font-weight: 700;
            font-size: 13px;
        }

        .dropdown {
            display: none;
            position: absolute;
            top: 40px; right: 0;
            background: #fff;
            border: 1px solid #ddd;
            border-radius: 3px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            min-width: 160px;
            z-index: 200;
        }

        .user-menu:hover .dropdown { display: block; }

        .dropdown a {
            display: block;
            padding: 10px 16px;
            color: #333;
            text-decoration: none;
            font-size: 13px;
        }

        .dropdown a:hover { background: #f0f0f0; }
        .dropdown hr { border: none; border-top: 1px solid #eee; margin: 4px 0; }

        /* ── Layout ── */
        #content {
            margin-top: 50px;
            display: flex;
            min-height: calc(100vh - 50px);
        }

        /* ── Sidebar ── */
        #sidebar {
            width: 220px;
            background: #fff;
            border-right: 1px solid #ddd;
            padding: 16px 0;
            flex-shrink: 0;
        }

        .sidebar-nav a {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 9px 20px;
            color: #555;
            text-decoration: none;
            font-size: 13px;
            transition: background 0.1s;
        }

        .sidebar-nav a:hover,
        .sidebar-nav a.active {
            background: #e8f4fb;
            color: #0082c9;
        }

        .sidebar-nav a.active { font-weight: 600; }

        .sidebar-icon { font-size: 16px; width: 20px; text-align: center; }

        .sidebar-section-label {
            padding: 14px 20px 4px;
            font-size: 11px;
            text-transform: uppercase;
            color: #aaa;
            letter-spacing: 0.5px;
        }

        /* ── Main File Area ── */
        #main {
            flex: 1;
            padding: 24px 32px;
            max-width: 1100px;
        }

        .breadcrumb {
            font-size: 16px;
            color: #0082c9;
            margin-bottom: 20px;
        }

        .breadcrumb span { color: #333; }

        /* Action bar */
        .action-bar {
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 20px;
        }

        .btn {
            padding: 8px 18px;
            border: none;
            border-radius: 3px;
            font-size: 13px;
            cursor: pointer;
            transition: background 0.15s;
        }

        .btn-primary {
            background: #0082c9;
            color: #fff;
        }

        .btn-primary:hover { background: #006dac; }

        .btn-outline {
            background: #fff;
            color: #555;
            border: 1px solid #ccc;
        }

        .btn-outline:hover { background: #f4f4f4; }

        /* Hidden file input */
        #upload-input { display: none; }

        /* File table */
        .file-table {
            width: 100%;
            border-collapse: collapse;
            background: #fff;
            border-radius: 4px;
            overflow: hidden;
            box-shadow: 0 1px 4px rgba(0,0,0,0.08);
        }

        .file-table th {
            text-align: left;
            padding: 11px 14px;
            font-size: 12px;
            font-weight: 600;
            color: #888;
            text-transform: uppercase;
            letter-spacing: 0.4px;
            background: #fafafa;
            border-bottom: 1px solid #eee;
        }

        .file-table td {
            padding: 11px 14px;
            border-bottom: 1px solid #f0f0f0;
            vertical-align: middle;
        }

        .file-table tr:last-child td { border-bottom: none; }

        .file-table tr:hover td { background: #f8fbff; }

        .file-name-cell {
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 14px;
        }

        .file-icon { font-size: 18px; }

        .file-table .size-col { color: #888; font-size: 13px; }
        .file-table .date-col { color: #888; font-size: 13px; white-space: nowrap; }
        .file-table .action-col { text-align: right; }

        .file-tag {
            display: inline-block;
            padding: 2px 7px;
            background: #e8f4fb;
            color: #0082c9;
            border-radius: 2px;
            font-size: 11px;
            font-weight: 600;
            margin-left: 6px;
        }

        /* Quota bar */
        .quota-bar {
            margin-top: 30px;
            font-size: 12px;
            color: #888;
        }

        .quota-track {
            height: 5px;
            background: #e0e0e0;
            border-radius: 3px;
            margin-top: 6px;
            overflow: hidden;
        }

        .quota-fill {
            height: 100%;
            background: #0082c9;
            width: 48%;
            border-radius: 3px;
        }

        /* Toast notification */
        .toast {
            position: fixed;
            bottom: 24px;
            right: 24px;
            background: #2d9a2d;
            color: #fff;
            padding: 14px 20px;
            border-radius: 4px;
            font-size: 14px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.2);
            animation: slideIn 0.3s ease;
            z-index: 500;
        }

        .toast-error {
            background: #c0392b;
        }

        @keyframes slideIn {
            from { transform: translateY(20px); opacity: 0; }
            to   { transform: translateY(0);    opacity: 1; }
        }
    </style>
</head>
<body>

<!-- ── Top Bar ── -->
<div id="header">
    <a class="header-logo" href="#">
        <svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
            <path d="M73 57a14 14 0 00-6-26.5 18 18 0 00-34 8A12 12 0 0028 60h45a5 5 0 000-3z"
                  fill="#fff" opacity="0.95"/>
        </svg>
        ownCloud
    </a>

    <nav class="header-nav">
        <a href="#" class="active">Files</a>
        <a href="#">Activity</a>
        <a href="#">Photos</a>
        <a href="#">Music</a>
        <a href="#">Documents</a>
    </nav>

    <div class="header-right">
        <span class="search-icon" title="Search">🔍</span>
        <div class="user-menu">
            <div class="avatar"><?= strtoupper(substr(htmlspecialchars($oc_user, ENT_QUOTES, 'UTF-8'), 0, 1)) ?></div>
            <span><?= htmlspecialchars($oc_user, ENT_QUOTES, 'UTF-8') ?></span>
            <span>▾</span>
            <div class="dropdown">
                <a href="#">Settings</a>
                <a href="#">Personal</a>
                <hr>
                <a href="?logout=1">Log out</a>
            </div>
        </div>
    </div>
</div>

<!-- ── Main Layout ── -->
<div id="content">

    <!-- ── Sidebar ── -->
    <div id="sidebar">
        <nav class="sidebar-nav">
            <a href="#" class="active"><span class="sidebar-icon">🗂️</span> All files</a>
            <a href="#"><span class="sidebar-icon">⭐</span> Favorites</a>
            <a href="#"><span class="sidebar-icon">🕒</span> Recent</a>
        </nav>

        <div class="sidebar-section-label">Sharing</div>
        <nav class="sidebar-nav">
            <a href="#"><span class="sidebar-icon">👤</span> Shared with you</a>
            <a href="#"><span class="sidebar-icon">↗️</span> Shared with others</a>
            <a href="#"><span class="sidebar-icon">🔗</span> Shared by link</a>
        </nav>

        <div class="sidebar-section-label">Tags</div>
        <nav class="sidebar-nav">
            <a href="#"><span class="sidebar-icon">🏷️</span> All tags</a>
        </nav>

        <div class="quota-bar" style="padding: 20px;">
            2.4 GB used of 5 GB
            <div class="quota-track"><div class="quota-fill"></div></div>
        </div>
    </div>

    <!-- ── File Area ── -->
    <div id="main">
        <div class="breadcrumb">Files <span>/ Home</span></div>

        <!-- Action bar with upload trigger -->
        <div class="action-bar">
            <button class="btn btn-primary" onclick="document.getElementById('upload-input').click()">
                ↑ Upload
            </button>
            <button class="btn btn-outline">+ New folder</button>
            <form id="upload-form" method="post" enctype="multipart/form-data" style="display:none">
                <input type="file" id="upload-input" name="file"
                       onchange="document.getElementById('upload-form').submit()">
            </form>
        </div>

        <!-- File listing table -->
        <table class="file-table">
            <thead>
                <tr>
                    <th style="width:40px"></th>
                    <th>Name ↑</th>
                    <th style="width:100px">Size</th>
                    <th style="width:130px">Modified</th>
                    <th style="width:60px"></th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($fake_files as $f): ?>
                <tr>
                    <td><input type="checkbox"></td>
                    <td>
                        <div class="file-name-cell">
                            <span class="file-icon"><?= $f['type'] === 'folder' ? '📁' : '📄' ?></span>
                            <?= htmlspecialchars($f['name'], ENT_QUOTES, 'UTF-8') ?>
                        </div>
                    </td>
                    <td class="size-col"><?= fmt_size($f['size']) ?></td>
                    <td class="date-col"><?= fmt_date($f['mtime']) ?></td>
                    <td class="action-col">···</td>
                </tr>
                <?php endforeach; ?>

                <?php foreach ($captured_files as $f): ?>
                <tr>
                    <td><input type="checkbox"></td>
                    <td>
                        <div class="file-name-cell">
                            <span class="file-icon"><?= file_icon($f['name']) ?></span>
                            <?= htmlspecialchars($f['name'], ENT_QUOTES, 'UTF-8') ?>
                            <span class="file-tag">uploaded</span>
                        </div>
                    </td>
                    <td class="size-col"><?= fmt_size($f['size']) ?></td>
                    <td class="date-col"><?= fmt_date($f['mtime']) ?></td>
                    <td class="action-col">···</td>
                </tr>
                <?php endforeach; ?>

                <?php if (empty($captured_files) && empty($fake_files)): ?>
                <tr>
                    <td colspan="5" style="text-align:center;padding:40px;color:#aaa;">
                        No files yet. Upload something to get started.
                    </td>
                </tr>
                <?php endif; ?>
            </tbody>
        </table>
    </div>
</div>

<?php if ($upload_toast): ?>
    <div class="toast" id="toast">
        ✔ <?= $upload_toast ?> was uploaded
    </div>
    <script>setTimeout(() => { document.getElementById('toast').style.display = 'none'; }, 4000);</script>
<?php endif; ?>

<?php if ($upload_error): ?>
    <div class="toast toast-error" id="toast-error">
        ✖ <?= htmlspecialchars($upload_error, ENT_QUOTES, 'UTF-8') ?>
    </div>
    <script>setTimeout(() => { document.getElementById('toast-error').style.display = 'none'; }, 4000);</script>
<?php endif; ?>

</body>
</html>
