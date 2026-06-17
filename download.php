<?php
/**
 * download.php — Secure file download with mandatory password prompt
 */
require_once 'config.php';

$token = $_GET["token"] ?? "";

$stmt = $conn->prepare("SELECT * FROM uploads WHERE share_token = ?");
$stmt->execute([$token]);
$file = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$file) die("File not found.");

$toegang = false;
$debug_reason = '';

// 1. No password → automatic access
if (empty($file["password"])) {
    $toegang = true;
    $debug_reason = 'No password set';
}

// 2. Session unlock (set by verify.php after correct password)
if (!$toegang && isset($_SESSION['unlocked_tokens'][$token]) && $_SESSION['unlocked_tokens'][$token] === true) {
    $toegang = true;
    $debug_reason = 'Session unlocked';
}

// 3. Owner bypass: REMOVED – even owners must enter password.

// If access granted and download parameter present, serve file
if ($toegang && (isset($_GET["download"]) || isset($_GET["direct"]))) {
    $path = "uploads/" . $file["stored_name"];
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

// If we reach here, access is not granted – show modal (or error)
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title><?= htmlspecialchars($file["original_name"]) ?> — kevinstopmettelaatkomen</title>
<link rel="stylesheet" href="style.css">
</head>
<body>

<div class="auth-page">
<div class="card auth-card download-card">

<?php if ($toegang): ?>
<!-- Access granted – show file info and download button -->
<div class="auth-header">
<div class="logo-mark">
<?= strpos($file["mime_type"], "image/") === 0 ? "🖼️" : "📄" ?>
</div>
<h1><?= htmlspecialchars($file["original_name"]) ?></h1>
<?php if (!empty($file["password"])): ?>
<p style="color: var(--text-muted); font-size: 0.8rem;">🔒 Password‑protected (unlocked)</p>
<?php endif; ?>
<!-- Debug: remove after testing -->
<p style="color: #888; font-size:0.7rem;">Access granted because: <?= $debug_reason ?></p>
</div>

<?php if (strpos($file["mime_type"], "image/") === 0): ?>
<img src="uploads/<?= htmlspecialchars($file["stored_name"]) ?>" alt="<?= htmlspecialchars($file["original_name"]) ?>" style="width:100%; border-radius: var(--radius-md); margin-bottom: 1.25rem; display:block;">
<?php else: ?>
<div class="alert" style="background: var(--bg-surface); border-color: var(--border); color: var(--text-secondary); margin-bottom: 1.25rem;">
<?= htmlspecialchars(strtoupper(pathinfo($file["original_name"], PATHINFO_EXTENSION))) ?> file ready for download.
</div>
<?php endif; ?>

<a href="?token=<?= htmlspecialchars($token) ?>&download=1" class="btn btn-primary btn-full">
Download Securely
</a>

<?php else: ?>
<!-- Password required – show modal immediately -->
<div class="auth-header">
<div class="logo-mark">🔐</div>
<h1><?= htmlspecialchars($file["original_name"]) ?></h1>
<p>This file is password‑protected.</p>
</div>

<div id="passwordModal" class="modal-overlay" style="display:flex;">
<div class="modal-card">
<div class="modal-header">
<span class="modal-title">🔐 Enter password</span>
<button class="modal-close" id="modalClose">&times;</button>
</div>
<form id="passwordForm">
<p style="margin-bottom: 1rem;">The file <strong><?= htmlspecialchars($file["original_name"]) ?></strong> is password‑protected.</p>
<input type="hidden" name="token" id="modalToken" value="<?= htmlspecialchars($token) ?>">
<input type="hidden" name="action" value="download">
<div class="form-group">
<label for="modalPassword">Password</label>
<input type="password" id="modalPassword" name="password" placeholder="Enter download password" required autofocus>
</div>
<button type="submit" class="btn btn-primary btn-full">Unlock & Download</button>
</form>
<div id="modalError" class="alert alert-danger" style="display:none; margin-top: 1rem;"></div>
</div>
</div>

<style>
.modal-overlay {
    position: fixed;
    inset: 0;
    background: rgba(0,0,0,0.7);
    backdrop-filter: blur(6px);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 1000;
    padding: 1rem;
}
.modal-card {
    background: var(--bg-surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    padding: 2rem;
    max-width: 420px;
    width: 100%;
    box-shadow: var(--shadow-card);
    position: relative;
}
.modal-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1.5rem;
}
.modal-title {
    font-size: 1.25rem;
    font-weight: 600;
    color: var(--text-primary);
}
.modal-close {
    background: none;
    border: none;
    color: var(--text-muted);
    font-size: 1.75rem;
    cursor: pointer;
    line-height: 1;
    transition: color var(--transition);
}
.modal-close:hover {
    color: var(--text-primary);
}
</style>

<script>
const modal = document.getElementById('passwordModal');
const closeBtn = document.getElementById('modalClose');
const form = document.getElementById('passwordForm');
const errorDiv = document.getElementById('modalError');
const passwordInput = document.getElementById('modalPassword');
const token = document.getElementById('modalToken').value;

closeBtn.addEventListener('click', function() {
    modal.style.display = 'none';
});
modal.addEventListener('click', function(e) {
    if (e.target === modal) {
        modal.style.display = 'none';
    }
});

form.addEventListener('submit', function(e) {
    e.preventDefault();
    const password = passwordInput.value;
    errorDiv.style.display = 'none';

const formData = new FormData();
formData.append('token', token);
                      formData.append('password', password);
                      formData.append('action', 'download');

                      fetch('verify.php', {
                          method: 'POST',
                          body: formData
                      })
                      .then(response => response.json())
                      .then(data => {
                          if (data.success) {
                              window.location.href = '?token=' + encodeURIComponent(token) + '&download=1';
                          } else {
                              errorDiv.textContent = data.error || 'Wrong password.';
                      errorDiv.style.display = 'block';
                      passwordInput.value = '';
                      passwordInput.focus();
                          }
                      })
                      .catch(err => {
                          errorDiv.textContent = 'An error occurred. Please try again.';
                      errorDiv.style.display = 'block';
                      console.error(err);
                      });
});
</script>
<?php endif; ?>

</div>
</div>

</body>
</html>
