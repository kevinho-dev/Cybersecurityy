<?php
require_once 'config.php';

if (!isset($_SESSION['user_id'])) {
    $t = $_GET['token'] ?? ''; $next = preg_match('/^[a-f0-9]{64}$/', $t) ? urlencode("download.php?token=$t") : urlencode('download.php');
    header("Location: login.php?next=$next"); exit;
}

 $token = $_GET["token"] ?? ""; $tokenNotFound = false; $fatalError = ""; $toegang = false; $file = false;

if (!preg_match('/^[a-f0-9]{64}$/', $token)) $tokenNotFound = true;
else {
    $stmt = $conn->prepare("SELECT uploads.*, users.username AS owner_username FROM uploads JOIN users ON users.id = uploads.user_id WHERE share_token = ?");
    $stmt->execute([$token]); $file = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$file) $tokenNotFound = true;
}

if (!$tokenNotFound && $file) {
    if (empty($file["password"])) $toegang = true;
    if (!$toegang && isset($_SESSION['unlocked_tokens'][$token])) $toegang = true;

    if ($toegang && (isset($_GET["download"]) || isset($_GET["direct"]))) {
        $path = __DIR__ . '/../uploads/' . $file["stored_name"]; $real = realpath($path); $dir = realpath(__DIR__ . '/../uploads/');
        if ($real && $dir && strpos($real, $dir) === 0 && is_file($real)) {
            logEvent($conn, 'download', $file['user_id'], $file['owner_username'], $file['original_name']);
            $ascii = preg_replace('/[^\x20-\x7E]/', '_', $file["original_name"]);
            header("Content-Type: " . $file["mime_type"]); header("Content-Disposition: attachment; filename=\"$ascii\"; filename*=UTF-8''" . rawurlencode($file["original_name"]));
            header("Content-Length: " . filesize($real)); header("X-Content-Type-Options: nosniff"); header("Cache-Control: no-store");
            if (ob_get_level()) ob_end_clean(); readfile($real); exit;
        } else $fatalError = "File missing on server.";
    }
}

render_head($tokenNotFound ? "Not found" : htmlspecialchars($file["original_name"]), false, '../css/style.css');
echo '<div class="card auth-card download-card">';
if ($tokenNotFound) echo '<div class="auth-header"><div class="logo-mark">⚠️</div><h1>File not found</h1><p>This link is invalid or removed.</p></div>';
elseif ($fatalError) { echo '<div class="auth-header"><div class="logo-mark">⚠️</div><h1>'.htmlspecialchars($file["original_name"]).'</h1></div>'; render_alerts([$fatalError]); }
elseif ($toegang) {
    echo '<div class="auth-header"><div class="logo-mark">'.(strpos($file["mime_type"], "image/") === 0 ? "🖼️" : "📄").'</div><h1>'.htmlspecialchars($file["original_name"]).'</h1>';
    if (!empty($file["password"])) echo '<p style="color: var(--text-muted); font-size: 0.8rem;">🔒 Unlocked</p>';
    echo '</div>';
    if (strpos($file["mime_type"], "image/") === 0) echo '<img src="thumbnail.php?token='.htmlspecialchars($token).'" alt="" style="width:100%; border-radius: var(--radius-md); margin-bottom: 1.25rem; display:block;">';
    else echo '<div class="alert" style="background: var(--bg-surface); border-color: var(--border); color: var(--text-secondary); margin-bottom: 1.25rem;">'.htmlspecialchars(strtoupper(pathinfo($file["original_name"], PATHINFO_EXTENSION))).' file ready.</div>';
    echo '<a href="?token='.htmlspecialchars($token).'&download=1" class="btn btn-primary btn-full">Download Securely</a>';
} else {
    echo '<div class="auth-header"><div class="logo-mark">🔐</div><h1>'.htmlspecialchars($file["original_name"]).'</h1><p>This file is password‑protected.</p></div>';
    render_modal(['token' => $token, 'filename' => $file["original_name"], 'verifyUrl' => 'verify.php', 'successUrl' => '?token={token}&download=1', 'isOpen' => true]);
}
echo '</div>';
render_foot(false, '../js/app.js');