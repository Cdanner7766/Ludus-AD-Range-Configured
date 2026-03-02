<?php
// Ludus Corporation Employee Portal — Login Page
// VULN: SQL injection on the email field (no prepared statements)
// VULN: DB credentials hardcoded in source (admin:admin)
// VULN: PHP display_errors leaks full PDO exception messages to the browser

session_start();
if (!empty($_SESSION['lc_logged_in'])) {
    header('Location: home.php');
    exit;
}

$error    = '';
$db_error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = $_POST['email']    ?? '';
    $pass  = $_POST['password'] ?? '';

    // Derive DB01 IP from server's own address — DB01 is always .41 on same /24
    $parts  = explode('.', $_SERVER['SERVER_ADDR'] ?? '10.10.10.31');
    $dbHost = "{$parts[0]}.{$parts[1]}.{$parts[2]}.41";

    $authenticated = false;

    try {
        // VULN: weak credentials used for DB connection
        $dsn = "mysql:host=$dbHost;dbname=ccdc_company;charset=utf8;connect_timeout=4";
        $pdo = new PDO($dsn, 'admin', 'admin', [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);

        // VULN: SQL injection — $email is concatenated directly into the query.
        // Bypass with:  ' OR 1=1 LIMIT 1 -- -
        $sql  = "SELECT id, name, email FROM employees WHERE email='$email'";
        $stmt = $pdo->query($sql);
        $row  = $stmt ? $stmt->fetch(PDO::FETCH_ASSOC) : null;

        if ($row && $pass !== '') {
            // VULN: any non-empty password accepted once a DB row is matched
            $authenticated            = true;
            $_SESSION['lc_logged_in'] = true;
            $_SESSION['lc_user']      = $row['name'];
            $_SESSION['lc_email']     = $row['email'];
        }
    } catch (Exception $e) {
        // VULN: full exception message written to page (display_errors = On amplifies this)
        $db_error = $e->getMessage();
    }

    // Fallback: hardcoded admin backdoor credential
    if (!$authenticated && $email === 'admin' && $pass === 'admin') {
        $authenticated            = true;
        $_SESSION['lc_logged_in'] = true;
        $_SESSION['lc_user']      = 'Administrator';
        $_SESSION['lc_email']     = 'admin@ludus.domain';
    }

    if ($authenticated) {
        header('Location: home.php');
        exit;
    }

    $error = 'Invalid email address or password.';
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Ludus Corporation — Employee Portal</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, sans-serif;
      background: linear-gradient(140deg, #0f2748 0%, #1d4ed8 100%);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
    }
    .card {
      background: #fff;
      border-radius: 12px;
      padding: 44px 40px 36px;
      width: 380px;
      box-shadow: 0 24px 64px rgba(0,0,0,.3);
    }
    .brand {
      text-align: center;
      margin-bottom: 32px;
    }
    .brand-icon {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 52px; height: 52px;
      background: #0f2748;
      border-radius: 10px;
      margin-bottom: 12px;
      font-size: 26px;
      color: #fff;
    }
    .brand-name {
      font-size: 20px;
      font-weight: 800;
      color: #0f172a;
      letter-spacing: -.4px;
    }
    .brand-sub {
      font-size: 12.5px;
      color: #64748b;
      margin-top: 3px;
    }
    label {
      display: block;
      font-size: 13px;
      font-weight: 600;
      color: #374151;
      margin-bottom: 6px;
    }
    input[type="text"], input[type="password"] {
      display: block;
      width: 100%;
      padding: 10px 13px;
      border: 1px solid #d1d5db;
      border-radius: 7px;
      font-size: 14px;
      color: #111827;
      margin-bottom: 18px;
      transition: border-color .15s, box-shadow .15s;
    }
    input:focus {
      outline: none;
      border-color: #1d4ed8;
      box-shadow: 0 0 0 3px rgba(29,78,216,.12);
    }
    .btn {
      display: block;
      width: 100%;
      padding: 11px;
      background: #0f2748;
      color: #fff;
      font-size: 14px;
      font-weight: 600;
      border: none;
      border-radius: 7px;
      cursor: pointer;
      transition: background .15s;
      margin-top: 6px;
    }
    .btn:hover { background: #1d4ed8; }
    .alert {
      padding: 10px 13px;
      border-radius: 7px;
      font-size: 13px;
      margin-bottom: 18px;
    }
    .alert-error {
      background: #fef2f2;
      border: 1px solid #fecaca;
      color: #b91c1c;
    }
    .alert-db {
      background: #fefce8;
      border: 1px solid #fde68a;
      color: #92400e;
      font-size: 11px;
      word-break: break-all;
    }
    .divider {
      border: none;
      border-top: 1px solid #f1f5f9;
      margin: 24px 0 16px;
    }
    .hint {
      text-align: center;
      font-size: 12px;
      color: #94a3b8;
    }
    footer {
      margin-top: 24px;
      color: rgba(255,255,255,.55);
      font-size: 12px;
      text-align: center;
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="brand">
      <div class="brand-icon">&#x1F3E2;</div>
      <div class="brand-name">Ludus Corporation</div>
      <div class="brand-sub">Employee Portal &mdash; Internal Access Only</div>
    </div>

    <?php if ($error): ?>
      <div class="alert alert-error"><?= htmlspecialchars($error) ?></div>
    <?php endif; ?>

    <?php if ($db_error): ?>
      <div class="alert alert-db"><strong>Database error:</strong> <?= htmlspecialchars($db_error) ?></div>
    <?php endif; ?>

    <form method="POST" autocomplete="off">
      <label for="email">Email Address</label>
      <input type="text" id="email" name="email"
             placeholder="you@ludus.domain"
             value="<?= htmlspecialchars($_POST['email'] ?? '') ?>">

      <label for="password">Password</label>
      <input type="password" id="password" name="password" placeholder="Enter your password">

      <button type="submit" class="btn">Sign In &rarr;</button>
    </form>

    <hr class="divider">
    <p class="hint">Contact IT Help Desk for login issues &mdash; ext. 4357</p>
  </div>

  <footer>&copy; <?= date('Y') ?> Ludus Corporation. All rights reserved. Unauthorized access is prohibited.</footer>
</body>
</html>
