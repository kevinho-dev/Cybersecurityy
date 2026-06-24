<?php
require_once 'php/config.php';

// Only logged-in users may access the dashboard.
require_auth('php/login.php');

$shareLink  = '';
$error      = '';
$imageMimes = get_image_mimes();

// If the page was redirected here after a successful upload, show the share link.
// We validate the token format to avoid reflecting arbitrary strings into the page.
if (isset($_GET['link']) && preg_match('/^[a-f0-9]{64}$/', $_GET['link'])) {
    $scheme    = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https://' : 'http://';
    $base      = rtrim(dirname($_SERVER['PHP_SELF']), '/\\');
    $shareLink = $scheme . $_SERVER['HTTP_HOST'] . $base . '/php/download.php?token=' . htmlspecialchars($_GET['link']);
}

// ─────────────────────────────────────────────────────────────────────────────
// FILE UPLOAD HANDLER
// ─────────────────────────────────────────────────────────────────────────────

if (isset($_POST['submit'])) {
    if (!verifyCsrf()) {
        $error = 'Invalid request.';
    } elseif (empty($_FILES['fileToUpload']['tmp_name'])) {
        $error = 'Select a file.';
    } else {
        $result = handle_upload($conn, $_FILES['fileToUpload'], $_POST['password'] ?? '');

        // handle_upload() returns the 64-character share token on success,
        // or a human-readable error string on failure.
        if (preg_match('/^[a-f0-9]{64}$/', $result)) {
            // Redirect with the token in the URL so the share link box appears.
            // PRG (Post/Redirect/Get) pattern prevents double-submission on refresh.
            header('Location: ?link=' . $result);
            exit;
        }
        $error = $result;
    }
}

/**
 * Validates and stores one uploaded file.
 *
 * Returns the 64-character share token string on success.
 * Returns a human-readable error message string on failure.
 */
function handle_upload(PDO $conn, array $file, string $password): string
{
    // Map allowed file extensions to their expected MIME types.
    // We check BOTH the extension AND the actual file content MIME type.
    // Checking only the extension is not safe — a .jpg could contain PHP code.
    $allowed = [
        'jpg'  => 'image/jpeg',
        'jpeg' => 'image/jpeg',
        'png'  => 'image/png',
        'gif'  => 'image/gif',
        'webp' => 'image/webp',
        'pdf'  => 'application/pdf',
        'doc'  => 'application/msword',
        'docx' => 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'xls'  => 'application/vnd.ms-excel',
        'xlsx' => 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'txt'  => 'text/plain',
    ];

    $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));

    // finfo reads the actual file contents to determine the MIME type.
    // This cannot be spoofed by simply renaming the file.
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mime  = finfo_file($finfo, $file['tmp_name']);
    finfo_close($finfo);

    // Both checks must pass — the extension must be in our whitelist AND the
    // real MIME type must match what we expect for that extension.
    if (!isset($allowed[$ext]) || $allowed[$ext] !== $mime) {
        return 'Invalid file type.';
    }
    if ($file['size'] > 25_000_000) {
        return 'Max 25 MB.';
    }
    // Require a minimum password length to protect downloads.
    if (empty($password) || strlen($password) < 4) {
        return 'Password min 4 chars.';
    }

    // Deduplicate uploads: if this user already uploaded the exact same file,
    // return the existing token instead of creating a second copy on disk.
    $hash = hash_file('sha256', $file['tmp_name']);
    $stmt = $conn->prepare("SELECT share_token FROM uploads WHERE file_hash = ? AND user_id = ?");
    $stmt->execute([$hash, $_SESSION['user_id']]);
    $existing = $stmt->fetch();
    if ($existing) {
        return $existing['share_token'];
    }

    // Store the file under a random name so the original filename is never
    // exposed via the filesystem, server logs, or directory listings.
    if (!is_dir('uploads')) {
        mkdir('uploads', 0750, true);
    }
    $storedName = bin2hex(random_bytes(16)) . '.' . $ext;
    move_uploaded_file($file['tmp_name'], 'uploads/' . $storedName);

    // Generate a unique share token (64 hex chars = 256 bits of randomness).
    $token = bin2hex(random_bytes(32));

    $conn->prepare(
        "INSERT INTO uploads (user_id, share_token, original_name, stored_name, mime_type, file_hash, password)
    VALUES (?, ?, ?, ?, ?, ?, ?)"
    )->execute([
        $_SESSION['user_id'],
        $token,
        basename($file['name']),        // basename() strips any path prefix from the filename.
               $storedName,
               $mime,
               $hash,
               password_hash($password, PASSWORD_DEFAULT),  // Never store a plain-text password.
    ]);

    logEvent($conn, 'upload', $_SESSION['user_id'], $_SESSION['username'], basename($file['name']));
    return $token;
}


// ─────────────────────────────────────────────────────────────────────────────
// LOAD FILE LIST
// Fetch all files uploaded by the current user, newest first.
// ─────────────────────────────────────────────────────────────────────────────

$stmt = $conn->prepare(
    "SELECT original_name, share_token, mime_type, uploaded_at
    FROM uploads WHERE user_id = ? ORDER BY uploaded_at DESC"
);
$stmt->execute([$_SESSION['user_id']]);
$uploads = $stmt->fetchAll();

// ─────────────────────────────────────────────────────────────────────────────
// LOAD FILES SHARED WITH THE CURRENT USER
// Joins shared_files → uploads → users to get all metadata in one query.
// Only rows where shared_with = current user are returned — enforcing that
// users can only see files explicitly shared with them.
// ─────────────────────────────────────────────────────────────────────────────

$stmt = $conn->prepare(
    "SELECT u.original_name, u.share_token, u.mime_type, u.uploaded_at,
    sf.shared_at,
    sender.username AS sender_username,
    u.stored_name,
    u.id AS upload_id,
    sf.id AS share_id
    FROM shared_files sf
    JOIN uploads u   ON u.id  = sf.upload_id
    JOIN users sender ON sender.id = sf.shared_by
    WHERE sf.shared_with = ?
    ORDER BY sf.shared_at DESC"
);
$stmt->execute([$_SESSION['user_id']]);
$sharedWithMe = $stmt->fetchAll();

render_head('Dashboard');
?>

<div class="page-header">
<h1>Upload file</h1>
<p>Upload and protect with a password.</p>
</div>

<div class="card mb-md">
<form method="post" enctype="multipart/form-data" class="upload-form">
<?= csrfField() ?>
<div class="upload-zone">
<input type="file" name="fileToUpload" id="fileToUpload"
accept="image/*,.pdf,.doc,.docx,.xls,.xlsx,.txt" required>
<span class="upload-label">Click or drag a file here</span>
<span class="upload-hint">JPG, PNG, GIF, WebP, PDF, Word, Excel, TXT · max 25 MB</span>
</div>
<div id="filePreview" class="file-preview" style="display:none;">
<div class="file-preview-thumb" id="filePreviewThumb"></div>
<div class="file-preview-info">
<span class="file-preview-name" id="filePreviewName"></span>
<span class="file-preview-size" id="filePreviewSize"></span>
</div>
<button type="button" class="file-preview-remove" id="filePreviewRemove" title="Remove">&times;</button>
</div>
<div class="upload-row">
<div class="form-group">
<label for="dl-password">Download password</label>
<input type="password" id="dl-password" name="password"
placeholder="Min 4 chars"
required autocomplete="new-password" minlength="4">
</div>
<button type="submit" name="submit" class="btn btn-primary">Upload</button>
</div>
</form>
<?php render_alerts([$error]); ?>
<?php if ($shareLink): ?>
<div class="share-link-box">
<span class="share-label">Share link generated</span>
<a href="<?= $shareLink ?>" target="_blank" rel="noopener"><?= $shareLink ?></a>
</div>
<?php endif; ?>
</div>

<div class="divider-label">My uploaded files</div>

<?php if ($uploads): ?>
<div class="file-table-wrapper">
<table>
<thead>
<tr>
<th>Filename</th>
<th>Share link</th>
<th>Share with user</th>
<th>Direct download</th>
<th>Date</th>
</tr>
</thead>
<tbody>
<?php foreach ($uploads as $upload): ?>
<tr>
<td>
<div class="file-cell">
<span class="file-cell-thumb">
<?php if (in_array($upload['mime_type'], $imageMimes)): ?>
<img src="php/thumbnail.php?token=<?= htmlspecialchars($upload['share_token']) ?>"
alt="" loading="lazy">
<?php else: ?>
📄
<?php endif; ?>
</span>
<span><?= htmlspecialchars($upload['original_name']) ?></span>
</div>
</td>
<td>
<!-- data-* attributes are read by app.js to populate the password modal. -->
<button class="file-link action-btn"
data-token="<?= htmlspecialchars($upload['share_token']) ?>"
data-filename="<?= htmlspecialchars($upload['original_name']) ?>"
data-action="share">Share link</button>
</td>
<td>
<button class="file-link action-btn"
data-token="<?= htmlspecialchars($upload['share_token']) ?>"
data-filename="<?= htmlspecialchars($upload['original_name']) ?>"
data-action="share_with_user">Share with user</button>
</td>
<td>
<button class="btn btn-primary action-btn"
style="padding:.4rem 1rem; font-size:.85rem"
data-token="<?= htmlspecialchars($upload['share_token']) ?>"
data-filename="<?= htmlspecialchars($upload['original_name']) ?>"
data-action="download">Download</button>
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
<div style="font-size:2.5rem; margin-bottom:.75rem">📂</div>
<p>No files uploaded yet.</p>
</div>
</div>
<?php endif; ?>

<!-- The modal is hidden by default; app.js opens it when a button is clicked. -->
<?php render_modal(['verifyUrl' => 'php/verify.php', 'successUrl' => 'php/download.php?token={token}&direct=1']); ?>

<!-- ═══════════════════════════════════════════════════════════════════════════
FILES SHARED WITH ME
Only files where another user explicitly shared to the current user appear here.
Sender username, file type, size, and share date are shown.
Download action requires password verification (handled by download.php).
═══════════════════════════════════════════════════════════════════════════ -->

<div class="divider-label">Files shared with me</div>

<?php if ($sharedWithMe): ?>
<div class="file-table-wrapper">
<table>
<thead>
<tr>
<th>Filename</th>
<th>Type</th>
<th>Shared by</th>
<th>Date shared</th>
<th>Action</th>
</tr>
</thead>
<tbody>
<?php foreach ($sharedWithMe as $shared): ?>
<tr>
<td>
<div class="file-cell">
<span class="file-cell-thumb">
<?php if (in_array($shared['mime_type'], $imageMimes)): ?>
🖼️
<?php else: ?>
📄
<?php endif; ?>
</span>
<span><?= htmlspecialchars($shared['original_name']) ?></span>
</div>
</td>
<td><?= htmlspecialchars(strtoupper(pathinfo($shared['original_name'], PATHINFO_EXTENSION))) ?></td>
<td>
<span style="display:inline-flex; align-items:center; gap:.35rem;">
👤 <?= htmlspecialchars($shared['sender_username']) ?>
</span>
</td>
<td><?= htmlspecialchars($shared['shared_at']) ?></td>
<td>
<!-- Opens download.php which enforces password verification before any access. -->
<a href="php/download.php?token=<?= htmlspecialchars($shared['share_token']) ?>"
class="btn btn-primary"
style="padding:.4rem 1rem; font-size:.85rem;">
View / Download
</a>
</td>
</tr>
<?php endforeach; ?>
</tbody>
</table>
</div>
<?php else: ?>
<div class="card">
<div class="empty-state">
<div style="font-size:2.5rem; margin-bottom:.75rem">📬</div>
<p>No files have been shared with you yet.</p>
</div>
</div>
<?php endif; ?>

<?php

// ── SHARE WITH USER MODAL ─────────────────────────────────────────────────────
// Shown when clicking "Share with user". Uses its own separate modal so it
// doesn't interfere with the password modal (#passwordModal).
echo '
<div id="shareUserModal" class="modal-overlay" style="display:none;">
<div class="modal-card">
<div class="modal-header">
<span class="modal-title">👤 Share with user</span>
<button class="modal-close" id="shareUserModalClose">&times;</button>
</div>
<p style="margin-bottom:1rem;">
Share <strong id="shareUserFilename"></strong> with another registered user.
They will see it in their "Files Shared With Me" table.
</p>
<div class="form-group">
<label for="shareUserInput">Username</label>
<input type="text" id="shareUserInput" placeholder="Enter username" autocomplete="off">
</div>
<button type="button" class="btn btn-primary btn-full" id="shareUserSubmit">Share</button>
<div id="shareUserError"  class="alert alert-danger"  style="display:none; margin-top:1rem;"></div>
<div id="shareUserSuccess" class="alert alert-success" style="display:none; margin-top:1rem;"></div>
</div>
</div>';
?>

<?php render_foot(); ?>
<?php // NOTE: render_foot() above closes </div></script></body></html>. ?>
