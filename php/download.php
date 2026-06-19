<?php
/**
 * download.php — public download page
 * Anyone with the link must enter the password — including the file owner.
 */
require_once 'config.php';

$token = $_GET["token"] ?? "";

$stmt = $conn->prepare("SELECT * FROM uploads WHERE share_token = ?");
$stmt->execute([$token]);
$file = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$file) die("File not found.");

$toegang = false;

// Grant access if the file has no password
if (empty($file["password"])) {
    $toegang = true;
}

// Grant access if verify.php already unlocked this token in the current session
if (!$toegang && isset($_SESSION['unlocked_tokens'][$token]) && $_SESSION['unlocked_tokens'][$token] === true) {
    $toegang = true;
}

// NOTE: No owner bypass — the owner must also enter the password every time.

// Access granted + download flag in URL → serve the file
if ($toegang && (isset($_GET["download"]) || isset($_GET["direct"]))) {
    $path = "../uploads/" . $file["stored_name"];
    if (file_exists($path)) {
        header("Content-Type: " . $file["mime_type"]);
        header("Content-Disposition: attachment; filename=\"" . addslashes($file["original_name"]) . "\"");
        header("Content-Length: " . filesize($path));
        header("X-Content-Type-Options: nosniff");
        if (ob_get_level()) ob_end_clean();
        readfile($path);
        exit;
    } else {
        die("File not found on server.");
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title><?= htmlspecialchars($file["original_name"]) ?> — kevinstopmettelaatkomen</title>
<link rel="stylesheet" href="../css/style.css">
</head>
<body>

<div class="auth-page">
<div class="card auth-card download-card">

<?php if ($toegang): ?>
<!-- Access granted: show file preview + download button -->
<div class="auth-header">
    <div class="logo-mark">
        <?= strpos($file["mime_type"], "image/") === 0 ? "🖼️" : "📄" ?>
    </div>
    <h1><?= htmlspecialchars($file["original_name"]) ?></h1>
    <?php if (!empty($file["password"])): ?>
        <p style="color: var(--text-muted); font-size: 0.8rem;">🔒 Password‑protected (unlocked)</p>
    <?php endif; ?>
</div>

<?php if (strpos($file["mime_type"], "image/") === 0): ?>
    <img src="../uploads/<?= htmlspecialchars($file["stored_name"]) ?>"
         alt="<?= htmlspecialchars($file["original_name"]) ?>"
         style="width:100%; border-radius: var(--radius-md); margin-bottom: 1.25rem; display:block;">
<?php else: ?>
    <div class="alert" style="background: var(--bg-surface); border-color: var(--border); color: var(--text-secondary); margin-bottom: 1.25rem;">
        <?= htmlspecialchars(strtoupper(pathinfo($file["original_name"], PATHINFO_EXTENSION))) ?> file ready for download.
    </div>
<?php endif; ?>

<a href="?token=<?= htmlspecialchars($token) ?>&download=1" class="btn btn-primary btn-full">
    Download Securely
</a>

<?php else: ?>
<!-- Access denied: show password modal straight away -->
<div class="auth-header">
    <div class="logo-mark">🔐</div>
    <h1><?= htmlspecialchars($file["original_name"]) ?></h1>
    <p>This file is password‑protected.</p>
</div>

<!-- Modal visible immediately (display:flex) -->
<div id="passwordModal" class="modal-overlay" style="display:flex;">
    <div class="modal-card">
        <div class="modal-header">
            <span class="modal-title">🔐 Enter password</span>
            <button class="modal-close" id="modalClose">&times;</button>
        </div>
        <form id="passwordForm">
            <p style="margin-bottom: 1rem;">
                The file <strong><?= htmlspecialchars($file["original_name"]) ?></strong> is password‑protected.
            </p>
            <!-- Token passed to JS so verify.php knows which file to check -->
            <input type="hidden" id="modalToken" value="<?= htmlspecialchars($token) ?>">
            <div class="form-group">
                <label for="modalPassword">Password</label>
                <input type="password" id="modalPassword" name="password"
                       placeholder="Enter download password" required autofocus>
            </div>
            <button type="submit" class="btn btn-primary btn-full">Unlock & Download</button>
        </form>
        <div id="modalError" class="alert alert-danger" style="display:none; margin-top: 1rem;"></div>
    </div>
</div>

<script src="../js/download.js"></script>
<?php endif; ?>

</div>
</div>

</body>
</html>