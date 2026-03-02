<?php
// Ludus Corporation Intranet — Employee Directory
// VULN: SQL injection in search (?q=)
// VULN: XSS — search term and employee data echoed without escaping
// VULN: Sensitive data (SSN, salary) exposed to any authenticated user

session_start();
if (empty($_SESSION['lc_logged_in'])) {
    header('Location: index.php');
    exit;
}
$user = htmlspecialchars($_SESSION['lc_user'] ?? 'Employee');

// VULN: search parameter not sanitized
$search   = $_GET['q'] ?? '';

// Derive DB01 IP from the web server's own address
$parts  = explode('.', $_SERVER['SERVER_ADDR'] ?? '10.10.10.31');
$dbHost = "{$parts[0]}.{$parts[1]}.{$parts[2]}.41";

$employees = [];
$db_error  = '';
$row_count = 0;

try {
    $dsn = "mysql:host=$dbHost;dbname=ccdc_company;charset=utf8;connect_timeout=4";
    // VULN: admin:admin credential used
    $pdo = new PDO($dsn, 'admin', 'admin', [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);

    if ($search !== '') {
        // VULN: SQL injection — $search concatenated directly into LIKE clause
        // Example payload: %' UNION SELECT 1,user(),database(),4,5 -- -
        $sql = "SELECT id, name, email, ssn, salary FROM employees
                WHERE name LIKE '%$search%' OR email LIKE '%$search%'";
    } else {
        $sql = "SELECT id, name, email, ssn, salary FROM employees ORDER BY name";
    }

    $stmt      = $pdo->query($sql);
    $employees = $stmt ? $stmt->fetchAll(PDO::FETCH_ASSOC) : [];
    $row_count = count($employees);

} catch (Exception $e) {
    // VULN: raw exception message printed (display_errors = On amplifies this)
    $db_error = $e->getMessage();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Employee Directory — Ludus Corporation</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #f1f5f9;
      color: #1e293b;
      font-size: 14px;
    }
    .header {
      background: #0f2748;
      color: #fff;
      height: 54px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0 28px;
      box-shadow: 0 1px 3px rgba(0,0,0,.2);
      position: sticky; top: 0; z-index: 10;
    }
    .header-brand { font-size: 16px; font-weight: 700; letter-spacing: -.3px; }
    .header-brand span { color: #93c5fd; }
    .header-nav { display: flex; align-items: center; gap: 6px; }
    .header-nav a {
      color: rgba(255,255,255,.75);
      text-decoration: none;
      padding: 6px 12px;
      border-radius: 5px;
      font-size: 13px;
      transition: background .15s;
    }
    .header-nav a:hover { background: rgba(255,255,255,.1); color: #fff; }
    .header-nav a.active { background: rgba(255,255,255,.15); color: #fff; }
    .header-user {
      display: flex; align-items: center; gap: 10px;
      color: rgba(255,255,255,.8); font-size: 13px;
    }
    .avatar {
      width: 30px; height: 30px;
      background: #1d4ed8; border-radius: 50%;
      display: flex; align-items: center; justify-content: center;
      font-weight: 700; font-size: 13px; color: #fff;
    }
    .header-user a {
      color: rgba(255,255,255,.6); text-decoration: none; font-size: 12px;
      border: 1px solid rgba(255,255,255,.2); padding: 4px 10px; border-radius: 5px;
    }
    .header-user a:hover { background: rgba(255,255,255,.1); color: #fff; }
    .main { max-width: 1080px; margin: 0 auto; padding: 32px 24px; }
    .toolbar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 20px;
      flex-wrap: wrap;
      gap: 12px;
    }
    .toolbar-title { font-size: 22px; font-weight: 700; color: #0f172a; }
    .search-form { display: flex; gap: 8px; }
    .search-form input[type="text"] {
      padding: 8px 13px;
      border: 1px solid #d1d5db;
      border-radius: 7px;
      font-size: 13px;
      width: 240px;
      transition: border-color .15s;
    }
    .search-form input:focus { outline: none; border-color: #1d4ed8; }
    .search-form button {
      padding: 8px 16px;
      background: #0f2748;
      color: #fff;
      border: none;
      border-radius: 7px;
      font-size: 13px;
      font-weight: 600;
      cursor: pointer;
      transition: background .15s;
    }
    .search-form button:hover { background: #1d4ed8; }
    .search-form a {
      padding: 8px 12px;
      border: 1px solid #d1d5db;
      border-radius: 7px;
      font-size: 13px;
      color: #64748b;
      text-decoration: none;
    }
    .search-form a:hover { background: #f8fafc; }
    .alert {
      padding: 10px 14px; border-radius: 7px; font-size: 13px;
      margin-bottom: 16px;
    }
    .alert-db { background: #fefce8; border: 1px solid #fde68a; color: #92400e; word-break: break-all; font-size: 12px; }
    .card { background: #fff; border: 1px solid #e2e8f0; border-radius: 10px; overflow: hidden; }
    .card-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 16px 20px;
      border-bottom: 1px solid #f1f5f9;
    }
    .card-header-title { font-size: 13px; font-weight: 700; color: #374151; }
    .record-count { font-size: 12px; color: #94a3b8; }
    table { width: 100%; border-collapse: collapse; }
    thead th {
      background: #f8fafc;
      padding: 11px 16px;
      text-align: left;
      font-size: 11.5px;
      font-weight: 700;
      color: #64748b;
      text-transform: uppercase;
      letter-spacing: .06em;
      border-bottom: 1px solid #e2e8f0;
    }
    tbody td {
      padding: 12px 16px;
      border-bottom: 1px solid #f1f5f9;
      font-size: 13.5px;
      vertical-align: middle;
    }
    tbody tr:last-child td { border-bottom: none; }
    tbody tr:hover td { background: #fafbfd; }
    .emp-name { font-weight: 600; color: #0f172a; }
    .emp-email { color: #1d4ed8; }
    .emp-ssn {
      font-family: 'SF Mono', 'Fira Code', 'Courier New', monospace;
      font-size: 12.5px;
      color: #dc2626;
      font-weight: 600;
    }
    .emp-salary { color: #15803d; font-weight: 600; }
    .badge-dept {
      display: inline-block;
      padding: 2px 9px;
      border-radius: 12px;
      font-size: 11.5px;
      font-weight: 600;
      background: #eff6ff;
      color: #1d4ed8;
    }
    .empty-state {
      text-align: center;
      padding: 48px 24px;
      color: #94a3b8;
      font-size: 14px;
    }
    .search-summary {
      font-size: 13px;
      color: #64748b;
      margin-bottom: 14px;
    }
    /* VULN: The .search-summary span is echoed raw — XSS lands here */
  </style>
</head>
<body>

<!-- ── Header ── -->
<header class="header">
  <div class="header-brand">&#x25A0; Ludus <span>Corporation</span></div>
  <nav class="header-nav">
    <a href="home.php">Home</a>
    <a href="employees.php" class="active">Employees</a>
    <a href="info.php" target="_blank">IT Info</a>
  </nav>
  <div class="header-user">
    <div class="avatar"><?= strtoupper(substr($user, 0, 1)) ?></div>
    <span><?= $user ?></span>
    <a href="logout.php">Sign out</a>
  </div>
</header>

<main class="main">
  <div class="toolbar">
    <div class="toolbar-title">Employee Directory</div>
    <form class="search-form" method="GET">
      <!-- VULN: $_GET['q'] is unsanitized in the SQL query above -->
      <input type="text" name="q" placeholder="Search name or email&hellip;"
             value="<?= htmlspecialchars($search) ?>">
      <button type="submit">Search</button>
      <?php if ($search): ?><a href="employees.php">Clear</a><?php endif; ?>
    </form>
  </div>

  <?php if ($db_error): ?>
    <div class="alert alert-db"><strong>Database error:</strong> <?= $db_error ?></div>
  <?php endif; ?>

  <?php if ($search): ?>
    <p class="search-summary">
      Showing results for: <strong><?= $search /* VULN: XSS — not escaped */ ?></strong>
      &mdash; <?= $row_count ?> record<?= $row_count !== 1 ? 's' : '' ?> found.
    </p>
  <?php endif; ?>

  <div class="card">
    <div class="card-header">
      <span class="card-header-title">All Employees</span>
      <span class="record-count"><?= $row_count ?> record<?= $row_count !== 1 ? 's' : '' ?></span>
    </div>

    <table>
      <thead>
        <tr>
          <th>Name</th>
          <th>Email</th>
          <th>Department</th>
          <th>SSN</th>
          <th>Salary</th>
        </tr>
      </thead>
      <tbody>
        <?php if (empty($employees)): ?>
          <tr><td colspan="5">
            <div class="empty-state">
              <?= $db_error ? 'Could not connect to database.' : 'No employees found.' ?>
            </div>
          </td></tr>
        <?php else: ?>
          <?php foreach ($employees as $emp): ?>
          <tr>
            <!-- VULN: employee fields echoed without htmlspecialchars (XSS if DB is compromised) -->
            <td class="emp-name"><?= $emp['name'] ?></td>
            <td class="emp-email"><?= $emp['email'] ?></td>
            <td><span class="badge-dept">Engineering</span></td>
            <td class="emp-ssn"><?= $emp['ssn'] ?></td>
            <td class="emp-salary">$<?= number_format((float)$emp['salary'], 2) ?></td>
          </tr>
          <?php endforeach; ?>
        <?php endif; ?>
      </tbody>
    </table>
  </div>
</main>

</body>
</html>
