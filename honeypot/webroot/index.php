<?php
session_start();

// Already authenticated — go straight to the file manager
if (isset($_SESSION['oc_auth']) && $_SESSION['oc_auth'] === true) {
    header('Location: dashboard.php');
    exit;
}

// Resolve real attacker IP (X-Forwarded-For for proxy/Docker NAT)
function resolve_ip(): string {
    $xff = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? null;
    if ($xff) {
        $ips = array_map('trim', explode(',', $xff));
        return $ips[0];
    }
    return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
}

$login_error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['user'] ?? '';
    $password = $_POST['password'] ?? '';

    // Log the credential attempt
    $log_dir = '/var/log/honeypot';
    if (!file_exists($log_dir)) {
        mkdir($log_dir, 0755, true);
    }
    $xff = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? null;
    $log_entry = json_encode([
        'timestamp'       => gmdate('Y-m-d\TH:i:s\Z'),
        'event'           => 'login_attempt',
        'username'        => $username,
        'password'        => $password,
        'ip'              => resolve_ip(),
        'x_forwarded_for' => $xff,
        'user_agent'      => $_SERVER['HTTP_USER_AGENT'] ?? '',
        'referer'         => $_SERVER['HTTP_REFERER'] ?? '',
    ], JSON_UNESCAPED_SLASHES) . "\n";
    file_put_contents('/var/log/honeypot/credentials.log', $log_entry, FILE_APPEND | LOCK_EX);

    // Artificial auth delay to look realistic (~800 ms)
    usleep(800000);

    // Accept any credentials — honeypot always "succeeds"
    $_SESSION['oc_auth'] = true;
    $_SESSION['oc_user'] = $username ?: 'admin';
    header('Location: dashboard.php');
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ownCloud</title>
    <style>
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            font-family: 'Open Sans', Arial, sans-serif;
            font-size: 14px;
            background: #1d2d44;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            color: #fff;
        }

        .login-box {
            background: #fff;
            border-radius: 4px;
            padding: 40px 40px 32px;
            width: 330px;
            box-shadow: 0 2px 20px rgba(0,0,0,0.4);
            color: #333;
        }

        .logo-wrap {
            text-align: center;
            margin-bottom: 28px;
        }

        /* OwnCloud cloud SVG logo */
        .logo-wrap svg {
            width: 62px;
            height: 62px;
        }

        .logo-wrap .brand {
            display: block;
            font-size: 22px;
            font-weight: 300;
            color: #0082c9;
            letter-spacing: -0.5px;
            margin-top: 6px;
        }

        label {
            display: block;
            font-size: 12px;
            color: #666;
            margin-bottom: 4px;
        }

        input[type="text"],
        input[type="password"] {
            width: 100%;
            padding: 10px 12px;
            border: 1px solid #ccc;
            border-radius: 3px;
            font-size: 14px;
            margin-bottom: 14px;
            outline: none;
            transition: border-color 0.15s;
        }

        input[type="text"]:focus,
        input[type="password"]:focus {
            border-color: #0082c9;
            box-shadow: 0 0 0 2px rgba(0,130,201,0.15);
        }

        .login-btn {
            width: 100%;
            padding: 11px;
            background: #0082c9;
            color: #fff;
            border: none;
            border-radius: 3px;
            font-size: 15px;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.15s;
            margin-top: 4px;
        }

        .login-btn:hover { background: #006dac; }

        .login-footer {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-top: 18px;
            font-size: 12px;
            color: #999;
        }

        .login-footer a {
            color: #0082c9;
            text-decoration: none;
        }

        .login-footer label {
            display: flex;
            align-items: center;
            gap: 5px;
            font-size: 12px;
            color: #666;
            margin: 0;
            cursor: pointer;
        }

        .version-info {
            margin-top: 24px;
            text-align: center;
            font-size: 11px;
            color: rgba(255,255,255,0.4);
        }

        .error-msg {
            background: #fce4e4;
            border: 1px solid #f5c6cb;
            border-radius: 3px;
            padding: 10px 12px;
            color: #721c24;
            font-size: 13px;
            margin-bottom: 14px;
        }
    </style>
</head>
<body>
    <div class="login-box">
        <div class="logo-wrap">
            <!-- OwnCloud cloud logo (simplified SVG) -->
            <svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
                <circle cx="50" cy="50" r="50" fill="#0082c9"/>
                <path d="M73 57a14 14 0 00-6-26.5 18 18 0 00-34 8A12 12 0 0028 60h45a5 5 0 000-3z"
                      fill="#fff" opacity="0.9"/>
            </svg>
            <span class="brand">ownCloud</span>
        </div>

        <?php if ($login_error): ?>
            <div class="error-msg"><?= htmlspecialchars($login_error, ENT_QUOTES, 'UTF-8') ?></div>
        <?php endif; ?>

        <form method="post" autocomplete="on">
            <label for="user">Username or email</label>
            <input type="text" id="user" name="user" autofocus autocomplete="username"
                   placeholder="Username or email" required>

            <label for="password">Password</label>
            <input type="password" id="password" name="password" autocomplete="current-password"
                   placeholder="Password" required>

            <button type="submit" class="login-btn">Log in</button>

            <div class="login-footer">
                <label>
                    <input type="checkbox" name="remember"> Remember login
                </label>
                <a href="#">Lost your password?</a>
            </div>
        </form>
    </div>

    <div class="version-info">ownCloud 10.12.0</div>
</body>
</html>
