<?php
/**
 * index.php — Upload & Dashboard
 */
require_once 'config.php';

if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit;
}

$shareLink = $error = "";

if (isset($_GET["link"])) {
    $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? "https://" : "http://";
    $host = $_SERVER['HTTP_HOST'];
    $path = rtrim(dirname($_SERVER['PHP_SELF']), '/\\');
    $shareLink = $protocol . $host . $path . "/download.php?token=" . htmlspecialchars($_GET["link"]);
}

// Upload processing
if (isset($_POST["submit"])) {
    $file = $_FILES["fileToUpload"];

    if (empty($file["tmp_name"])) {
        $error = "Select a file.";
    } else {
        $ext = strtolower(pathinfo($file["name"], PATHINFO_EXTENSION));

        $allowedTypes = [
            "jpg"  => "image/jpeg",
            "jpeg" => "image/jpeg",
            "png"  => "image/png",
            "gif"  => "image/gif",
            "webp" => "image/webp",
            "pdf"  => "application/pdf",
            "doc"  => "application/msword",
            "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "xls"  => "application/vnd.ms-excel",
            "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "txt"  => "text/plain",
        ];

        $finfo        = finfo_open(FILEINFO_MIME_TYPE);
        $detectedMime = finfo_file($finfo, $file["tmp_name"]);
        finfo_close($finfo);

        if (!array_key_exists($ext, $allowedTypes) || $allowedTypes[$ext] !== $detectedMime) {
            $error = "Invalid file type. Only images, PDF, Word, Excel, TXT allowed.";
        } elseif ($file["size"] > 25_000_000) {
            $error = "File too large. Max 25 MB.";
        } elseif (empty($_POST["password"])) {
            $error = "Enter a download password.";
        } else {
            $hash = hash_file("sha256", $file["tmp_name"]);
            $stmt = $conn->prepare("SELECT share_token FROM uploads WHERE file_hash = ? AND user_id = ?");
            $stmt->execute([$hash, $_SESSION['user_id']]);
            $existing = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($existing) {
                header("Location: ?link=" . $existing["share_token"]);
                exit;
            } else {
                if (!is_dir('uploads')) {
                    mkdir('uploads', 0777, true);
                }

                $stored = bin2hex(random_bytes(16)) . "." . $ext;
                move_uploaded_file($file["tmp_name"], "uploads/" . $stored);

                $token = bin2hex(random_bytes(32));
                $hashedPassword = password_hash($_POST["password"], PASSWORD_DEFAULT);

                $stmt = $conn->prepare(
                    "INSERT INTO uploads (user_id, share_token, original_name, stored_name, mime_type, file_hash, password)
                VALUES (?, ?, ?, ?, ?, ?, ?)"
                );
                $stmt->execute([
                    $_SESSION['user_id'],
                    $token,
                    basename($file["name"]),
                               $stored,
                               $detectedMime,
                               $hash,
                               $hashedPassword,
                ]);

                header("Location: ?link=" . $token);
                exit;
            }
        }
    }
}

// Fetch user's uploads
$stmt = $conn->prepare("SELECT original_name, share_token, uploaded_at FROM uploads WHERE user_id = ? ORDER BY uploaded_at DESC");
$stmt->execute([$_SESSION['user_id']]);
$myUploads = $stmt->fetchAll(PDO::FETCH_ASSOC);
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Dashboard — kevinstopmettelaatkomen</title>
<link rel="stylesheet" href="style.css">
</head>
<body>

<nav class="topbar">
<span class="brand">kevinstopmettelaatkomen</span>
<a href="logout.php" class="logout-link">Logout</a>
</nav>

<div class="page-wrapper">

<div class="page-header">
<h1>Upload file</h1>
<p>Upload an image or document and protect it with a password.</p>
</div>

<div class="card mb-md">
<form method="post" enctype="multipart/form-data" class="upload-form">

<div class="upload-zone">
<input type="file" name="fileToUpload" accept="image/*,.pdf,.doc,.docx,.xls,.xlsx,.txt" required>
<span class="upload-label">Click or drag a file here</span>
<span class="upload-hint">JPG, PNG, GIF, WebP, PDF, Word, Excel, TXT · max 25 MB</span>
</div>

<div class="upload-row">
<div class="form-group">
<label for="dl-password">Download password</label>
<input type="password" id="dl-password" name="password" placeholder="Choose a download password" required autocomplete="new-password">
</div>
<button type="submit" name="submit" class="btn btn-primary">
Upload
</button>
</div>

</form>

<?php if ($error): ?>
<div class="alert alert-danger"><?= htmlspecialchars($error) ?></div>
<?php endif; ?>

<?php if ($shareLink): ?>
<div class="share-link-box">
<span class="share-label">Share link generated</span>
<a href="<?= $shareLink ?>" target="_blank" rel="noopener"><?= $shareLink ?></a>
</div>
<script>history.replaceState(null, "", window.location.pathname);</script>
<?php endif; ?>
</div>

<div class="divider-label">My uploaded files</div>

<?php if (count($myUploads) > 0): ?>
<div class="file-table-wrapper">
<table>
<thead>
<tr>
<th>Filename</th>
<th>Share link</th>
<th>Direct download</th>
<th>Date uploaded</th>
</tr>
</thead>
<tbody>
<?php foreach ($myUploads as $upload): ?>
<tr>
<td><?= htmlspecialchars($upload['original_name']) ?></td>
<td>
<!-- Share link button: opens modal with action=share -->
<button class="file-link action-btn" data-token="<?= htmlspecialchars($upload['share_token']) ?>" data-filename="<?= htmlspecialchars($upload['original_name']) ?>" data-action="share" style="background:none; border:none; cursor:pointer; font-size:inherit; font-family:inherit; padding: 0.3rem 0.75rem;">
Share link
</button>
</td>
<td>
<!-- Download button: opens modal with action=download -->
<button class="btn btn-primary action-btn" style="padding: 0.4rem 1rem; font-size: 0.85rem;"
data-token="<?= htmlspecialchars($upload['share_token']) ?>"
data-filename="<?= htmlspecialchars($upload['original_name']) ?>"
data-action="download">
Download
</button>
</td>
<td><?= htmlspecialchars($upload['uploaded_at']) ?></td>
</tr>
<?php endforeach; ?>
</tbody>
</table>
</div>
<?php else: ?>
<div class="card">
<div class="empty-state">
<div style="font-size: 2.5rem; margin-bottom: 0.75rem;">📂</div>
<p>No files uploaded yet. Start above!</p>
</div>
</div>
<?php endif; ?>

</div>

<!-- ===== PASSWORD MODAL (reused for Download and Share) ===== -->
<div id="passwordModal" class="modal-overlay" style="display:none;">
<div class="modal-card">
<div class="modal-header">
<span class="modal-title">🔐 Enter password</span>
<button class="modal-close" id="modalClose">&times;</button>
</div>
<form id="passwordForm">
<p style="margin-bottom: 1rem;">The file <strong id="modalFilename"></strong> is password‑protected.</p>
<input type="hidden" name="token" id="modalToken">
<input type="hidden" name="action" id="modalAction">
<div class="form-group">
<label for="modalPassword">Password</label>
<input type="password" id="modalPassword" name="password" placeholder="Enter download password" required autofocus>
</div>
<button type="submit" class="btn btn-primary btn-full">Unlock</button>
</form>
<div id="modalError" class="alert alert-danger" style="display:none; margin-top: 1rem;"></div>
</div>
</div>

<style>
/* Modal styles */
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
    display: none;
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
// ========== OPEN MODAL ON ANY ACTION BUTTON ==========
const actionBtns = document.querySelectorAll('.action-btn');
const modal = document.getElementById('passwordModal');
const closeBtn = document.getElementById('modalClose');
const form = document.getElementById('passwordForm');
const tokenInput = document.getElementById('modalToken');
const actionInput = document.getElementById('modalAction');
const filenameSpan = document.getElementById('modalFilename');
const errorDiv = document.getElementById('modalError');
const passwordInput = document.getElementById('modalPassword');

actionBtns.forEach(btn => {
    btn.addEventListener('click', function(e) {
        e.preventDefault();
        const token = this.dataset.token;
        const filename = this.dataset.filename;
        const action = this.dataset.action;
        tokenInput.value = token;
        filenameSpan.textContent = filename;
        actionInput.value = action;
        errorDiv.style.display = 'none';
    passwordInput.value = '';
    modal.style.display = 'flex';
    passwordInput.focus();
    });
});

// Close modal
closeBtn.addEventListener('click', () => modal.style.display = 'none');
modal.addEventListener('click', (e) => { if (e.target === modal) modal.style.display = 'none'; });
document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && modal.style.display === 'flex') modal.style.display = 'none'; });

// ========== SUBMIT FORM TO verify.php ==========
form.addEventListener('submit', function(e) {
    e.preventDefault();
    const token = tokenInput.value;
    const password = passwordInput.value;
    const action = actionInput.value;
    errorDiv.style.display = 'none';

const formData = new FormData();
formData.append('token', token);
                      formData.append('password', password);
                      formData.append('action', action);

                      fetch('verify.php', {
                          method: 'POST',
                          body: formData
                      })
                      .then(response => response.json())
                      .then(data => {
                          if (data.success) {
                              // Password correct
                              if (action === 'download') {
                                  // Trigger download by redirecting to download.php with direct=1
                                  window.location.href = 'download.php?token=' + encodeURIComponent(token) + '&direct=1';
                              } else if (action === 'share') {
                                  // Build share URL and copy to clipboard
                                  const url = window.location.origin + window.location.pathname.replace(/\/index\.php$/, '') + '/download.php?token=' + encodeURIComponent(token);
                                  navigator.clipboard.writeText(url).then(() => {
                                      // Feedback: change button text? but we don't have reference to the original button.
                                      // We'll just show an alert or close modal with success message.
                                      alert('Share link copied to clipboard!');
                                      modal.style.display = 'none';
                                  }).catch(() => {
                                      alert('Could not copy. Please manually copy the link:\n' + url);
                                      modal.style.display = 'none';
                                  });
                              }
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

</body>
</html>
