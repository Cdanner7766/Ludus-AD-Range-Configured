<?php
// Ludus Corporation Intranet — Dashboard

session_start();
if (empty($_SESSION['lc_logged_in'])) {
    header('Location: index.php');
    exit;
}
$user = htmlspecialchars($_SESSION['lc_user']  ?? 'Employee');
$email= htmlspecialchars($_SESSION['lc_email'] ?? '');
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Ludus Corporation — Intranet</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #f1f5f9;
      color: #1e293b;
      font-size: 14px;
    }
    /* ── Header ── */
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
    .header-brand {
      font-size: 16px;
      font-weight: 700;
      letter-spacing: -.3px;
    }
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
      display: flex;
      align-items: center;
      gap: 10px;
      color: rgba(255,255,255,.8);
      font-size: 13px;
    }
    .avatar {
      width: 30px; height: 30px;
      background: #1d4ed8;
      border-radius: 50%;
      display: flex; align-items: center; justify-content: center;
      font-weight: 700; font-size: 13px; color: #fff;
    }
    .header-user a {
      color: rgba(255,255,255,.6);
      text-decoration: none;
      font-size: 12px;
      border: 1px solid rgba(255,255,255,.2);
      padding: 4px 10px;
      border-radius: 5px;
    }
    .header-user a:hover { background: rgba(255,255,255,.1); color: #fff; }
    /* ── Main ── */
    .main { max-width: 1080px; margin: 0 auto; padding: 32px 24px; }
    .page-title { font-size: 22px; font-weight: 700; color: #0f172a; margin-bottom: 24px; }
    .grid { display: grid; grid-template-columns: 2fr 1fr; gap: 20px; }
    @media (max-width: 720px) { .grid { grid-template-columns: 1fr; } }
    /* ── Card ── */
    .card {
      background: #fff;
      border: 1px solid #e2e8f0;
      border-radius: 10px;
      padding: 22px 24px;
    }
    .card-title {
      font-size: 11.5px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: .07em;
      color: #64748b;
      margin-bottom: 16px;
      padding-bottom: 12px;
      border-bottom: 1px solid #f1f5f9;
    }
    /* ── Announcements ── */
    .announcement {
      display: flex;
      gap: 14px;
      padding: 14px 0;
      border-bottom: 1px solid #f8fafc;
    }
    .announcement:last-child { border-bottom: none; padding-bottom: 0; }
    .ann-dot {
      flex-shrink: 0;
      width: 8px; height: 8px;
      border-radius: 50%;
      margin-top: 6px;
    }
    .dot-blue   { background: #1d4ed8; }
    .dot-yellow { background: #d97706; }
    .dot-green  { background: #16a34a; }
    .dot-red    { background: #dc2626; }
    .ann-body {}
    .ann-title { font-weight: 600; color: #0f172a; font-size: 14px; margin-bottom: 3px; }
    .ann-meta  { font-size: 12px; color: #94a3b8; }
    .ann-text  { font-size: 13px; color: #475569; margin-top: 5px; line-height: 1.5; }
    /* ── Quick links ── */
    .link-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
    .link-item {
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 12px 14px;
      border: 1px solid #e2e8f0;
      border-radius: 8px;
      text-decoration: none;
      color: #1e293b;
      transition: border-color .15s, box-shadow .15s;
    }
    .link-item:hover { border-color: #1d4ed8; box-shadow: 0 0 0 3px rgba(29,78,216,.08); }
    .link-icon {
      width: 34px; height: 34px;
      border-radius: 7px;
      display: flex; align-items: center; justify-content: center;
      font-size: 17px; flex-shrink: 0;
    }
    .icon-blue   { background: #eff6ff; }
    .icon-green  { background: #f0fdf4; }
    .icon-purple { background: #faf5ff; }
    .icon-orange { background: #fff7ed; }
    .link-label  { font-size: 13px; font-weight: 600; }
    /* ── Status list ── */
    .status-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 9px 0;
      border-bottom: 1px solid #f8fafc;
      font-size: 13px;
    }
    .status-row:last-child { border-bottom: none; }
    .status-badge {
      font-size: 11px;
      font-weight: 600;
      padding: 2px 8px;
      border-radius: 12px;
    }
    .badge-online { background: #dcfce7; color: #15803d; }
    .badge-warn   { background: #fef9c3; color: #a16207; }
    .badge-down   { background: #fee2e2; color: #b91c1c; }
    /* ── Welcome banner ── */
    .welcome-banner {
      background: linear-gradient(100deg, #0f2748 0%, #1d4ed8 100%);
      border-radius: 10px;
      padding: 22px 28px;
      color: #fff;
      margin-bottom: 24px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .welcome-title { font-size: 18px; font-weight: 700; }
    .welcome-sub   { font-size: 13px; color: rgba(255,255,255,.7); margin-top: 4px; }
    .welcome-date  { font-size: 13px; color: rgba(255,255,255,.6); text-align: right; }
  </style>
</head>
<body>

<!-- ── Header ── -->
<header class="header">
  <div class="header-brand">&#x25A0; Ludus <span>Corporation</span></div>
  <nav class="header-nav">
    <a href="home.php" class="active">Home</a>
    <a href="employees.php">Employees</a>
    <a href="info.php" target="_blank">IT Info</a>
  </nav>
  <div class="header-user">
    <div class="avatar"><?= strtoupper(substr($user, 0, 1)) ?></div>
    <span><?= $user ?></span>
    <a href="logout.php">Sign out</a>
  </div>
</header>

<main class="main">
  <!-- Welcome banner -->
  <div class="welcome-banner">
    <div>
      <div class="welcome-title">Welcome back, <?= $user ?>.</div>
      <div class="welcome-sub">Ludus Corporation Internal Portal</div>
    </div>
    <div class="welcome-date">
      <?= date('l, F j Y') ?><br>
      <span style="font-size:11px;opacity:.5;">Internal use only</span>
    </div>
  </div>

  <div class="grid">
    <!-- Left column: announcements + quick links -->
    <div>
      <!-- Announcements -->
      <div class="card" style="margin-bottom:20px;">
        <div class="card-title">Company Announcements</div>

        <div class="announcement">
          <div class="ann-dot dot-red"></div>
          <div class="ann-body">
            <div class="ann-title">Scheduled Network Maintenance — This Weekend</div>
            <div class="ann-meta">IT Operations &bull; <?= date('M j, Y') ?></div>
            <div class="ann-text">
              Core network infrastructure will be offline Saturday 02:00&ndash;06:00.
              VPN access and file shares will be unavailable during this window.
              Contact helpdesk at ext.&nbsp;4357 with questions.
            </div>
          </div>
        </div>

        <div class="announcement">
          <div class="ann-dot dot-blue"></div>
          <div class="ann-body">
            <div class="ann-title">Q3 Financial Report Now Available</div>
            <div class="ann-meta">Finance &bull; <?= date('M j, Y', strtotime('-3 days')) ?></div>
            <div class="ann-text">
              The Q3 earnings summary has been posted to the shared drive at
              <code>\\FILESVR\Shared\Finance\Q3_Report.xlsx</code>.
              All department heads should review before the Friday all-hands.
            </div>
          </div>
        </div>

        <div class="announcement">
          <div class="ann-dot dot-green"></div>
          <div class="ann-body">
            <div class="ann-title">New VPN Policy Effective Next Month</div>
            <div class="ann-meta">Information Security &bull; <?= date('M j, Y', strtotime('-7 days')) ?></div>
            <div class="ann-text">
              Multi-factor authentication will be required for all remote VPN connections.
              Employees must enroll their mobile device before the 1st. See the IT
              knowledge base for setup instructions.
            </div>
          </div>
        </div>

        <div class="announcement">
          <div class="ann-dot dot-yellow"></div>
          <div class="ann-body">
            <div class="ann-title">Office Closed — Company Holiday</div>
            <div class="ann-meta">HR &bull; <?= date('M j, Y', strtotime('-14 days')) ?></div>
            <div class="ann-text">
              All Ludus Corporation offices will be closed on the 25th for the
              company holiday. Essential IT services will remain monitored.
            </div>
          </div>
        </div>
      </div>

      <!-- Quick Links -->
      <div class="card">
        <div class="card-title">Quick Links</div>
        <div class="link-grid">
          <a href="employees.php" class="link-item">
            <div class="link-icon icon-blue">&#x1F465;</div>
            <div class="link-label">Employee Directory</div>
          </a>
          <a href="info.php" target="_blank" class="link-item">
            <div class="link-icon icon-purple">&#x2699;&#xFE0F;</div>
            <div class="link-label">System Info (PHP)</div>
          </a>
          <a href="mailto:helpdesk@ludus.domain" class="link-item">
            <div class="link-icon icon-green">&#x1F4E7;</div>
            <div class="link-label">IT Help Desk</div>
          </a>
          <a href="#" class="link-item">
            <div class="link-icon icon-orange">&#x1F4C1;</div>
            <div class="link-label">File Server</div>
          </a>
        </div>
      </div>
    </div>

    <!-- Right column: system status -->
    <div>
      <div class="card" style="margin-bottom:20px;">
        <div class="card-title">Infrastructure Status</div>
        <div class="status-row">
          <span>Web Server (WEB01)</span>
          <span class="status-badge badge-online">Online</span>
        </div>
        <div class="status-row">
          <span>Database (DB01)</span>
          <span class="status-badge badge-online">Online</span>
        </div>
        <div class="status-row">
          <span>Mail Server (MAIL01)</span>
          <span class="status-badge badge-online">Online</span>
        </div>
        <div class="status-row">
          <span>File Server (FILESVR)</span>
          <span class="status-badge badge-online">Online</span>
        </div>
        <div class="status-row">
          <span>DNS Server (DNS01)</span>
          <span class="status-badge badge-online">Online</span>
        </div>
        <div class="status-row">
          <span>Domain Controller</span>
          <span class="status-badge badge-online">Online</span>
        </div>
      </div>

      <div class="card">
        <div class="card-title">Your Account</div>
        <div class="status-row"><span>Name</span><span style="color:#0f172a;font-weight:600;"><?= $user ?></span></div>
        <div class="status-row"><span>Email</span><span style="color:#475569;"><?= $email ?></span></div>
        <div class="status-row"><span>Department</span><span style="color:#475569;">Engineering</span></div>
        <div class="status-row">
          <span>Session</span>
          <span class="status-badge badge-online">Active</span>
        </div>
      </div>
    </div>
  </div>
</main>

</body>
</html>
