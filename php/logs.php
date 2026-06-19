<?php
/**
 * logs.php — activity overview
 * Regular users: see their own uploads/downloads/login activity.
 * Admins: see activity from every user, with a "User" column.
 */
require_once 'config.php';

if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit;
}

$isAdmin = ($_SESSION['role'] ?? 'user') === 'admin';

// Get this user's username (needed to match login_failed rows, which have no user_id)
$stmt = $conn->prepare("SELECT username FROM users WHERE id = ?");
$stmt->execute([$_SESSION['user_id']]);
$me = $stmt->fetch(PDO::FETCH_ASSOC);

if ($isAdmin) {
    // Admins see every log entry, system-wide
    $stmt = $conn->query(
        "SELECT event_type, username, file_name, ip_address, details, created_at
         FROM logs
         ORDER BY created_at DESC
         LIMIT 500"
    );
    $logs = $stmt->fetchAll(PDO::FETCH_ASSOC);
} else {
    $stmt = $conn->prepare(
        "SELECT event_type, username, file_name, ip_address, details, created_at
         FROM logs
         WHERE user_id = ? OR username = ?
         ORDER BY created_at DESC
         LIMIT 200"
    );
    $stmt->execute([$_SESSION['user_id'], $me['username']]);
    $logs = $stmt->fetchAll(PDO::FETCH_ASSOC);
}

// Friendly labels per event type
$labels = [
    'upload'        => ['📤', 'File uploaded'],
    'download'      => ['📥', 'File downloaded'],
    'login_success' => ['✅', 'Successful login'],
    'login_failed'  => ['❌', 'Failed login attempt'],
    'unlock_failed' => ['🔒', 'Wrong download password entered'],
];
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Activity log — kevinstopmettelaatkomen</title>
<link rel="stylesheet" href="../css/style.css">
</head>
<body>

<nav class="topbar">
    <span class="brand">kevinstopmettelaatkomen</span>
    <a href="../index.php" class="logout-link">Dashboard</a>
    <a href="logout.php" class="logout-link">Logout</a>
</nav>

<div class="page-wrapper">

    <div class="page-header">
        <h1>Activity log <?= $isAdmin ? '<span style="font-size:0.6em; color: var(--text-muted);">(admin — all users)</span>' : '' ?></h1>
        <p><?= $isAdmin
            ? 'Uploads, downloads and login activity for every account on the system.'
            : 'Recent uploads, downloads and login activity on your account.' ?></p>
    </div>

    <?php if (count($logs) > 0): ?>
    <div class="file-table-wrapper">
        <table>
            <thead>
                <tr>
                    <th>Event</th>
                    <?php if ($isAdmin): ?><th>User</th><?php endif; ?>
                    <th>File</th>
                    <th>IP address</th>
                    <th>Date</th>
                </tr>
            </thead>
            <tbody>
            <?php foreach ($logs as $log): ?>
                <?php [$icon, $label] = $labels[$log['event_type']] ?? ['•', $log['event_type']]; ?>
                <tr>
                    <td><?= $icon ?> <?= htmlspecialchars($label) ?></td>
                    <?php if ($isAdmin): ?>
                        <td><?= htmlspecialchars($log['username'] ?? '—') ?></td>
                    <?php endif; ?>
                    <td><?= htmlspecialchars($log['file_name'] ?? '—') ?></td>
                    <td><?= htmlspecialchars($log['ip_address'] ?? '—') ?></td>
                    <td><?= htmlspecialchars($log['created_at']) ?></td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    <?php else: ?>
    <div class="card">
        <div class="empty-state">
            <div style="font-size: 2.5rem; margin-bottom: 0.75rem;">📋</div>
            <p>No activity logged yet.</p>
        </div>
    </div>
    <?php endif; ?>

</div>

</body>
</html>