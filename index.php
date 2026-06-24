<?php
require_once 'php/config.php'; require_auth('php/login.php');
 $shareLink = $error = ""; $imageMimes = get_image_mimes();

if (isset($_GET["link"]) && preg_match('/^[a-f0-9]{64}$/', $_GET["link"])) {
    $p = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? "https://" : "http://";
    $shareLink = $p . $_SERVER['HTTP_HOST'] . rtrim(dirname($_SERVER['PHP_SELF']), '/\\') . "/php/download.php?token=" . htmlspecialchars($_GET["link"]);
}

if (isset($_POST["submit"])) {
    if (!verifyCsrf()) $error = "Invalid request.";
    else {
        $file = $_FILES["fileToUpload"];
        if (empty($file["tmp_name"])) $error = "Select a file.";
        else {
            $ext = strtolower(pathinfo($file["name"], PATHINFO_EXTENSION));
            $allowed = ["jpg"=>"image/jpeg","jpeg"=>"image/jpeg","png"=>"image/png","gif"=>"image/gif","webp"=>"image/webp","pdf"=>"application/pdf","doc"=>"application/msword","docx"=>"application/vnd.openxmlformats-officedocument.wordprocessingml.document","xls"=>"application/vnd.ms-excel","xlsx"=>"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet","txt"=>"text/plain"];
            $finfo = finfo_open(FILEINFO_MIME_TYPE); $mime = finfo_file($finfo, $file["tmp_name"]); finfo_close($finfo);
            
            if (!isset($allowed[$ext]) || $allowed[$ext] !== $mime) $error = "Invalid file type.";
            elseif ($file["size"] > 25_000_000) $error = "Max 25 MB.";
            elseif (empty($_POST["password"]) || strlen($_POST["password"]) < 4) $error = "Password min 4 chars.";
            else {
                $hash = hash_file("sha256", $file["tmp_name"]);
                $stmt = $conn->prepare("SELECT share_token FROM uploads WHERE file_hash = ? AND user_id = ?"); $stmt->execute([$hash, $_SESSION['user_id']]); $ex = $stmt->fetch();
                if ($ex) { header("Location: ?link=" . $ex["share_token"]); exit; }
                else {
                    if (!is_dir('uploads')) mkdir('uploads', 0750, true);
                    $stored = bin2hex(random_bytes(16)) . "." . $ext; move_uploaded_file($file["tmp_name"], "uploads/" . $stored);
                    $token = bin2hex(random_bytes(32));
                    $conn->prepare("INSERT INTO uploads (user_id, share_token, original_name, stored_name, mime_type, file_hash, password) VALUES (?, ?, ?, ?, ?, ?, ?)")
                        ->execute([$_SESSION['user_id'], $token, basename($file["name"]), $stored, $mime, $hash, password_hash($_POST["password"], PASSWORD_DEFAULT)]);
                    logEvent($conn, 'upload', $_SESSION['user_id'], $_SESSION['username'], basename($file["name"]));
                    header("Location: ?link=" . $token); exit;
                }
            }
        }
    }
}

 $stmt = $conn->prepare("SELECT original_name, share_token, mime_type, uploaded_at FROM uploads WHERE user_id = ? ORDER BY uploaded_at DESC"); $stmt->execute([$_SESSION['user_id']]); $uploads = $stmt->fetchAll();

render_head('Dashboard');
?>
    <div class="page-header"><h1>Upload file</h1><p>Upload and protect with a password.</p></div>
    <div class="card mb-md">
        <form method="post" enctype="multipart/form-data" class="upload-form"><?= csrfField() ?>
            <div class="upload-zone"><input type="file" name="fileToUpload" id="fileToUpload" accept="image/*,.pdf,.doc,.docx,.xls,.xlsx,.txt" required><span class="upload-label">Click or drag a file here</span><span class="upload-hint">JPG, PNG, GIF, WebP, PDF, Word, Excel, TXT · max 25 MB</span></div>
            <div id="filePreview" class="file-preview" style="display:none;"><div class="file-preview-thumb" id="filePreviewThumb"></div><div class="file-preview-info"><span class="file-preview-name" id="filePreviewName"></span><span class="file-preview-size" id="filePreviewSize"></span></div><button type="button" class="file-preview-remove" id="filePreviewRemove" title="Remove">&times;</button></div>
            <div class="upload-row"><div class="form-group"><label for="dl-password">Download password</label><input type="password" id="dl-password" name="password" placeholder="Min 4 chars" required autocomplete="new-password" minlength="4"></div><button type="submit" name="submit" class="btn btn-primary">Upload</button></div>
        </form>
        <?= render_alerts([$error]) ?>
        <?php if ($shareLink): ?>
            <div class="share-link-box"><span class="share-label">Share link generated</span><a href="<?= $shareLink ?>" target="_blank" rel="noopener"><?= $shareLink ?></a></div>
            <script>history.replaceState(null, "", window.location.pathname);</script>
        <?php endif; ?>
    </div>
    <div class="divider-label">My uploaded files</div>
    <?php if (count($uploads) > 0): ?>
    <div class="file-table-wrapper"><table><thead><tr><th>Filename</th><th>Share link</th><th>Direct download</th><th>Date</th></tr></thead><tbody>
    <?php foreach ($uploads as $u): ?>
        <tr><td><div class="file-cell"><span class="file-cell-thumb"><?= in_array($u['mime_type'], $imageMimes) ? '<img src="php/thumbnail.php?token='.htmlspecialchars($u['share_token']).'" alt="" loading="lazy">' : '📄' ?></span><span><?= htmlspecialchars($u['original_name']) ?></span></div></td>
        <td><button class="file-link action-btn" data-token="<?= htmlspecialchars($u['share_token']) ?>" data-filename="<?= htmlspecialchars($u['original_name']) ?>" data-action="share">Share link</button></td>
        <td><button class="btn btn-primary action-btn" style="padding:.4rem 1rem;font-size:.85rem" data-token="<?= htmlspecialchars($u['share_token']) ?>" data-filename="<?= htmlspecialchars($u['original_name']) ?>" data-action="download">Download</button></td>
        <td><?= htmlspecialchars($u['uploaded_at']) ?></td></tr>
    <?php endforeach; ?>
    </tbody></table></div>
    <?php else: echo '<div class="card"><div class="empty-state"><div style="font-size:2.5rem;margin-bottom:.75rem">📂</div><p>No files uploaded yet.</p></div></div>'; endif; ?>
    
    <?= render_modal(['verifyUrl' => 'php/verify.php', 'successUrl' => 'php/download.php?token={token}&direct=1']) ?>
<?php render_foot(); ?>