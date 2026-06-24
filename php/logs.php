<?php
require_once 'config.php'; require_auth();
 $isAdmin = ($_SESSION['role'] ?? 'user') === 'admin';
 $stmt = $conn->prepare("SELECT username FROM users WHERE id = ?"); $stmt->execute([$_SESSION['user_id']]); $me = $stmt->fetch();

 $logs = $isAdmin ? $conn->query("SELECT event_type, username, file_name, ip_address, details, created_at FROM logs ORDER BY created_at DESC LIMIT 500")->fetchAll() : 
($conn->prepare("SELECT event_type, username, file_name, ip_address, details, created_at FROM logs WHERE user_id = ? OR username = ? ORDER BY created_at DESC LIMIT 200") && $stmt->execute([$_SESSION['user_id'], $me['username']]) ? $stmt->fetchAll() : []);

 $labels = ['upload'=>'📤 File uploaded','download'=>'📥 Downloaded','login_success'=>'✅ Login','login_failed'=>'❌ Failed login','unlock_failed'=>'🔒 Wrong password','rate_limited'=>'⏳ Rate limited'];

render_head('Activity log', false, '../css/style.css');
?>
    <div class="page-header"><h1>Activity log <?= $isAdmin ? '<span style="font-size:0.6em;color:var(--text-muted)">(admin)</span>' : '' ?></h1><p><?= $isAdmin ? 'System-wide.' : 'Your recent activity.' ?></p></div>
    <?php if (count($logs) > 0): ?>
    <div class="file-table-wrapper"><table><thead><tr><th>Event</th><?php if($isAdmin): ?><th>User</th><?php endif; ?><th>File</th><th>IP</th><th>Details</th><th>Date</th></tr></thead><tbody>
    <?php foreach ($logs as $l): ?>
        <tr><td><?= htmlspecialchars($labels[$l['event_type']] ?? $l['event_type']) ?></td><?php if($isAdmin): ?><td><?= htmlspecialchars($l['username'] ?? '—') ?></td><?php endif; ?><td><?= htmlspecialchars($l['file_name'] ?? '—') ?></td><td><?= htmlspecialchars($l['ip_address'] ?? '—') ?></td><td><?= htmlspecialchars($l['details'] ?? '—') ?></td><td><?= htmlspecialchars($l['created_at']) ?></td></tr>
    <?php endforeach; ?>
    </tbody></table></div>
    <?php else: echo '<div class="card"><div class="empty-state"><div style="font-size:2.5rem;margin-bottom:.75rem">📋</div><p>No activity.</p></div></div>'; endif; ?>
<?php render_foot(false, '../js/app.js'); ?>