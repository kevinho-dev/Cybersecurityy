<?php
require_once 'config.php';

// Only logged-in users may view the activity log.
require_auth();

// Check whether this user is an admin.
// Admins can see all events system-wide; regular users only see their own.
$isAdmin = ($_SESSION['role'] ?? 'user') === 'admin';

if ($isAdmin) {
    // Admins see everything, capped at 500 rows to keep the page fast.
    $logs = $conn->query(
        "SELECT event_type, username, file_name, ip_address, details, created_at
         FROM logs ORDER BY created_at DESC LIMIT 500"
    )->fetchAll();
} else {
    // Regular users see only events tied to their own user_id OR their username.
    // We match on both because some events (like failed logins) are logged before
    // the user_id is known, so only the username is recorded.
    $stmt = $conn->prepare(
        "SELECT event_type, username, file_name, ip_address, details, created_at
         FROM logs
         WHERE user_id = ? OR username = ?
         ORDER BY created_at DESC LIMIT 200"
    );

    // Look up the current user's username to match pre-auth events (like failed logins).
    $me = $conn->prepare("SELECT username FROM users WHERE id = ?");
    $me->execute([$_SESSION['user_id']]);
    $myUsername = $me->fetchColumn();

    $stmt->execute([$_SESSION['user_id'], $myUsername]);
    $logs = $stmt->fetchAll();
}

// Human-readable labels for the event type codes stored in the database.
$eventLabels = [
    'upload'        => '📤 File uploaded',
    'download'      => '📥 Downloaded',
    'login_success' => '✅ Login',
    'login_failed'  => '❌ Failed login',
    'unlock_failed' => '🔒 Wrong password',
    'rate_limited'  => '⏳ Rate limited',
];

render_head('Activity log', false, '../css/style.css');
?>
<div class="page-header">
    <h1>
        Activity log
        <?php if ($isAdmin): ?>
            <span style="font-size:0.6em; color:var(--text-muted)">(admin)</span>
        <?php endif; ?>
    </h1>
    <p><?= $isAdmin ? 'System-wide.' : 'Your recent activity.' ?></p>
</div>

<?php if ($logs): ?>
<div class="file-table-wrapper">
    <table>
        <thead>
            <tr>
                <th>Event</th>
                <?php if ($isAdmin): ?><th>User</th><?php endif; ?>
                <th>File</th>
                <th>IP</th>
                <th>Details</th>
                <th>Date</th>
            </tr>
        </thead>
        <tbody>
        <?php foreach ($logs as $log): ?>
            <tr>
                <!-- Use the human-readable label if we have one; fall back to the raw event code. -->
                <td><?= htmlspecialchars($eventLabels[$log['event_type']] ?? $log['event_type']) ?></td>
                <?php if ($isAdmin): ?>
                <td><?= htmlspecialchars($log['username']   ?? '—') ?></td>
                <?php endif; ?>
                <td><?= htmlspecialchars($log['file_name']  ?? '—') ?></td>
                <td><?= htmlspecialchars($log['ip_address'] ?? '—') ?></td>
                <td><?= htmlspecialchars($log['details']    ?? '—') ?></td>
                <td><?= htmlspecialchars($log['created_at']) ?></td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
</div>
<?php else: ?>
<div class="card">
    <div class="empty-state">
        <div style="font-size:2.5rem; margin-bottom:.75rem">📋</div>
        <p>No activity.</p>
    </div>
</div>
<?php endif; ?>

<?php render_foot(false, '../js/app.js'); ?>
