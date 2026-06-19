<?php
/**
 * index.php — Upload dashboard
 */
require_once 'php/config.php';

if (!isset($_SESSION['user_id'])) {
    header("Location: php/login.php");
    exit;
}

$shareLink = $error = "";

// After upload, ?link=TOKEN is set — build the full shareable URL
if (isset($_GET["link"])) {
    $protocol  = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? "https://" : "http://";
    $host      = $_SERVER['HTTP_HOST'];
    $path      = rtrim(dirname($_SERVER['PHP_SELF']), '/\\');
    $shareLink = $protocol . $host . $path . "/php/download.php?token=" . htmlspecialchars($_GET["link"]);
}

// ── Handle file upload ──────────────────────────────────────────
if (isset($_POST["submit"])) {
    $file = $_FILES["fileToUpload"];

    if (empty($file["tmp_name"])) {
        $error = "Select a file.";
    } else {
        $ext = strtolower(pathinfo($file["name"], PATHINFO_EXTENSION));

        // Allowed extensions mapped to their expected MIME types
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

        // Check real MIME type, not just the extension
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
            // Hash file contents to detect duplicates for this user
            $hash = hash_file("sha256", $file["tmp_name"]);
            $stmt = $conn->prepare("SELECT share_token FROM uploads WHERE file_hash = ? AND user_id = ?");
            $stmt->execute([$hash, $_SESSION['user_id']]);
            $existing = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($existing) {
                header("Location: ?link=" . $existing["share_token"]);
                exit;
            } else {
                if (!is_dir('uploads')) mkdir('uploads', 0777, true);

                // Random filename so the original name can't be guessed via URL
                $stored = bin2hex(random_bytes(16)) . "." . $ext;
                move_uploaded_file($file["tmp_name"], "uploads/" . $stored);

                $token          = bin2hex(random_bytes(32));
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

// Fetch the logged-in user's files for the table
$stmt = $conn->prepare("SELECT original_name, share_token, mime_type, uploaded_at FROM uploads WHERE user_id = ? ORDER BY uploaded_at DESC");
$stmt->execute([$_SESSION['user_id']]);
$myUploads = $stmt->fetchAll(PDO::FETCH_ASSOC);
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Dashboard — kevinstopmettelaatkomen</title>
<link rel="stylesheet" href="css/style.css">
</head>
<body>

<nav class="topbar">
    <span class="brand">kevinstopmettelaatkomen</span>
    <a href="php/logout.php" class="logout-link">Logout</a>
</nav>

<div class="page-wrapper">

    <div class="page-header">
        <h1>Upload file</h1>
        <p>Upload an image or document and protect it with a password.</p>
    </div>

    <div class="card mb-md">
        <form method="post" enctype="multipart/form-data" class="upload-form">

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
                <button type="button" class="file-preview-remove" id="filePreviewRemove" title="Remove file">&times;</button>
            </div>

            <div class="upload-row">
                <div class="form-group">
                    <label for="dl-password">Download password</label>
                    <input type="password" id="dl-password" name="password"
                           placeholder="Choose a download password"
                           required autocomplete="new-password">
                </div>
                <button type="submit" name="submit" class="btn btn-primary">Upload</button>
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
            <!-- Remove ?link= from the address bar so a refresh doesn't re-show this -->
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
                    <td>
                        <div class="file-cell">
                            <?php
                            $imageMimes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
                            $isImage = in_array($upload['mime_type'], $imageMimes);
                            ?>
                            <span class="file-cell-thumb">
                                <?php if ($isImage): ?>
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
                        <!-- Copies the download URL to clipboard; password enforced on download page -->
                        <button class="file-link action-btn"
                                data-token="<?= htmlspecialchars($upload['share_token']) ?>"
                                data-filename="<?= htmlspecialchars($upload['original_name']) ?>"
                                data-action="share">
                            Share link
                        </button>
                    </td>
                    <td>
                        <!-- Opens password modal before triggering the download -->
                        <button class="btn btn-primary action-btn"
                                style="padding: 0.4rem 1rem; font-size: 0.85rem;"
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

<!-- ── Password modal ── -->
<div id="passwordModal" class="modal-overlay" style="display:none;">
    <div class="modal-card">
        <div class="modal-header">
            <span class="modal-title">🔐 Enter password</span>
            <button class="modal-close" id="modalClose">&times;</button>
        </div>
        <form id="passwordForm">
            <p style="margin-bottom: 1rem;">
                The file <strong id="modalFilename"></strong> is password‑protected.
            </p>
            <input type="hidden" id="modalToken">
            <input type="hidden" id="modalAction">
            <div class="form-group">
                <label for="modalPassword">Password</label>
                <input type="password" id="modalPassword" name="password"
                       placeholder="Enter download password" required>
            </div>
            <button type="submit" class="btn btn-primary btn-full">Unlock</button>
        </form>
        <div id="modalError" class="alert alert-danger" style="display:none; margin-top: 1rem;"></div>
    </div>
</div>

<script src="js/dashboard.js"></script>

</body>
</html>