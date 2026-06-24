<?php
require_once 'config.php';

// ─────────────────────────────────────────────────────────────────────────────
// AUTHENTICATION GATE
// Only logged-in users may access this page.
// If the user isn't logged in, redirect them to login and preserve the download
// URL in ?next= so they come straight back here after logging in.
// ─────────────────────────────────────────────────────────────────────────────

if (!isset($_SESSION['user_id'])) {
    $token = $_GET['token'] ?? '';

    // Only include a ?next= redirect if the token looks valid.
    // An invalid token can't succeed after login anyway.
    $next = preg_match('/^[a-f0-9]{64}$/', $token)
        ? urlencode("download.php?token=$token")
        : urlencode('download.php');

    header("Location: login.php?next=$next");
    exit;
}


// ─────────────────────────────────────────────────────────────────────────────
// FILE LOOKUP
// Find the file in the database using the share token from the URL.
// ─────────────────────────────────────────────────────────────────────────────

$token = $_GET['token'] ?? '';

// Default states for the three possible outcomes on this page.
$fileNotFound  = false;
$fatalError    = '';
$accessGranted = false;
$file          = false;

// Reject obviously malformed tokens before touching the database.
if (!preg_match('/^[a-f0-9]{64}$/', $token)) {
    $fileNotFound = true;
} else {
    // Join with users so we can show the owner's username in the log.
    $stmt = $conn->prepare(
        "SELECT uploads.*, users.username AS owner_username
         FROM uploads
         JOIN users ON users.id = uploads.user_id
         WHERE share_token = ?"
    );
    $stmt->execute([$token]);
    $file = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$file) {
        $fileNotFound = true;
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// ACCESS CONTROL
// A file can only be accessed if:
//   (a) It has no password — anyone logged in may download it.
//   (b) The user already unlocked it this session via verify.php.
// ─────────────────────────────────────────────────────────────────────────────

if (!$fileNotFound && $file) {
    if (empty($file['password'])) {
        // No password required.
        $accessGranted = true;
    } elseif (isset($_SESSION['unlocked_tokens'][$token])) {
        // User entered the correct password earlier in this session.
        $accessGranted = true;
    }


    // ─────────────────────────────────────────────────────────────────────────
    // FILE SERVING
    // If access is granted and the user clicked Download, send the actual file.
    // ─────────────────────────────────────────────────────────────────────────

    if ($accessGranted && (isset($_GET['download']) || isset($_GET['direct']))) {
        $uploadsDir = realpath(__DIR__ . '/../uploads/');
        $filePath   = realpath(__DIR__ . '/../uploads/' . $file['stored_name']);

        // PATH-TRAVERSAL GUARD
        // A malicious stored_name like "../../etc/passwd" could escape the uploads
        // folder. realpath() resolves the final absolute path, and we check that
        // it starts with the uploads directory path.
        //
        // We append DIRECTORY_SEPARATOR so a folder named "uploads_evil/" cannot
        // trick the str_starts_with() check (since "uploads_evil" starts with "uploads").
        $pathIsValid = $filePath
            && $uploadsDir
            && str_starts_with($filePath, $uploadsDir . DIRECTORY_SEPARATOR)
            && is_file($filePath);

        if ($pathIsValid) {
            logEvent($conn, 'download', $file['user_id'], $file['owner_username'], $file['original_name']);

            // RFC 5987 dual filename encoding:
            //   filename="..."        → ASCII fallback for old browsers
            //   filename*=UTF-8''...  → full Unicode filename for modern browsers
            $asciiName = preg_replace('/[^\x20-\x7E]/', '_', $file['original_name']);
            header('Content-Type: '         . $file['mime_type']);
            header('Content-Disposition: attachment; filename="' . $asciiName . '"; filename*=UTF-8\'\'' . rawurlencode($file['original_name']));
            header('Content-Length: '       . filesize($filePath));
            header('X-Content-Type-Options: nosniff');
            header('Cache-Control: no-store');

            // Clear any output buffering so the file bytes aren't mixed with HTML.
            if (ob_get_level()) ob_end_clean();
            readfile($filePath);
            exit;
        }

        $fatalError = 'File missing on server.';
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// PAGE RENDERING
// Show different content based on what state we ended up in above.
// ─────────────────────────────────────────────────────────────────────────────

$pageTitle = $fileNotFound ? 'Not found' : htmlspecialchars($file['original_name']);
render_head($pageTitle, false, '../css/style.css');
echo '<div class="card auth-card download-card">';

if ($fileNotFound) {
    // Unknown token — don't reveal whether the file ever existed.
    echo '<div class="auth-header">
            <div class="logo-mark">⚠️</div>
            <h1>File not found</h1>
            <p>This link is invalid or removed.</p>
          </div>';

} elseif ($fatalError) {
    // File record exists in the database but the file is gone from disk.
    echo '<div class="auth-header">
            <div class="logo-mark">⚠️</div>
            <h1>' . htmlspecialchars($file['original_name']) . '</h1>
          </div>';
    render_alerts([$fatalError]);

} elseif ($accessGranted) {
    // User has access — show a preview and the Download button.
    $isImage = str_starts_with($file['mime_type'], 'image/');
    $icon    = $isImage ? '🖼️' : '📄';
    $ext     = strtoupper(pathinfo($file['original_name'], PATHINFO_EXTENSION));

    echo '<div class="auth-header">
            <div class="logo-mark">' . $icon . '</div>
            <h1>' . htmlspecialchars($file['original_name']) . '</h1>';
    if (!empty($file['password'])) {
        echo '<p style="color: var(--text-muted); font-size: 0.8rem;">🔒 Unlocked</p>';
    }
    echo '</div>';

    if ($isImage) {
        // Show a thumbnail preview for image files.
        echo '<img src="thumbnail.php?token=' . htmlspecialchars($token) . '" alt=""
                   style="width:100%; border-radius: var(--radius-md); margin-bottom: 1.25rem; display:block;">';
    } else {
        echo '<div class="alert" style="background: var(--bg-surface); border-color: var(--border);
                   color: var(--text-secondary); margin-bottom: 1.25rem;">'
           . htmlspecialchars($ext) . ' file ready.</div>';
    }

    echo '<a href="?token=' . htmlspecialchars($token) . '&download=1" '
       . 'class="btn btn-primary btn-full">Download Securely</a>';

} else {
    // File is password-protected and the user hasn't unlocked it yet.
    // Show the password modal immediately (isOpen: true).
    echo '<div class="auth-header">
            <div class="logo-mark">🔐</div>
            <h1>' . htmlspecialchars($file['original_name']) . '</h1>
            <p>This file is password&#8209;protected.</p>
          </div>';
    render_modal([
        'token'      => $token,
        'filename'   => $file['original_name'],
        'verifyUrl'  => 'verify.php',
        'successUrl' => '?token={token}&download=1',
        'isOpen'     => true,
    ]);
}

echo '</div>';
render_foot(false, '../js/app.js');
