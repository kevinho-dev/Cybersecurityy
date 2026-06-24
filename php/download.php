<?php
require_once 'config.php';

// ─────────────────────────────────────────────────────────────────────────────
// AUTHENTICATION GATE
// Only logged-in users may access this page.
// ─────────────────────────────────────────────────────────────────────────────

if (!isset($_SESSION['user_id'])) {
    $token = $_GET['token'] ?? '';
    $next  = preg_match('/^[a-f0-9]{64}$/', $token)
        ? urlencode("download.php?token=$token")
        : urlencode('download.php');
    header("Location: login.php?next=$next");
    exit;
}


// ─────────────────────────────────────────────────────────────────────────────
// FILE LOOKUP
// ─────────────────────────────────────────────────────────────────────────────

$token = $_GET['token'] ?? '';

$fileNotFound  = false;
$fatalError    = '';
$accessGranted = false;
$file          = false;

if (!preg_match('/^[a-f0-9]{64}$/', $token)) {
    $fileNotFound = true;
} else {
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
//
// SECURITY CHANGE: Password MUST be verified before showing ANY file info.
//   - No file name, no preview, no metadata until password is entered.
//   - Both the preview page AND the download action require verified session.
//   - Direct URL access to ?download=1 without session unlock is blocked.
// ─────────────────────────────────────────────────────────────────────────────

if (!$fileNotFound && $file) {
    if (empty($file['password'])) {
        // File has no password — anyone logged in may access it.
        $accessGranted = true;
    } elseif (isset($_SESSION['unlocked_tokens'][$token])) {
        // User entered the correct password earlier in this session.
        $accessGranted = true;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // FILE SERVING
    // SECURITY: Only serve the file if access is granted AND session is unlocked.
    // Attempting ?download=1 without a valid unlocked session redirects to
    // the password form — it cannot be bypassed.
    // ─────────────────────────────────────────────────────────────────────────

    if (isset($_GET['download']) || isset($_GET['direct'])) {
        // Hard gate: if not verified, do NOT serve the file — redirect to password page.
        if (!$accessGranted) {
            // Strip download/direct params so we land on the password form.
            header('Location: ?token=' . urlencode($token));
            exit;
        }

        $uploadsDir = realpath(__DIR__ . '/../uploads/');
        $filePath   = realpath(__DIR__ . '/../uploads/' . $file['stored_name']);

        $pathIsValid = $filePath
            && $uploadsDir
            && str_starts_with($filePath, $uploadsDir . DIRECTORY_SEPARATOR)
            && is_file($filePath);

        if ($pathIsValid) {
            logEvent($conn, 'download', $file['user_id'], $file['owner_username'], $file['original_name']);

            // Clear the session unlock so the user must re-enter the password
            // for any subsequent download of this file.
            unset($_SESSION['unlocked_tokens'][$token]);

            $asciiName = preg_replace('/[^\x20-\x7E]/', '_', $file['original_name']);
            header('Content-Type: '         . $file['mime_type']);
            header('Content-Disposition: attachment; filename="' . $asciiName . '"; filename*=UTF-8\'\'' . rawurlencode($file['original_name']));
            header('Content-Length: '       . filesize($filePath));
            header('X-Content-Type-Options: nosniff');
            header('Cache-Control: no-store');

            if (ob_get_level()) ob_end_clean();
            readfile($filePath);
            exit;
        }

        $fatalError = 'File missing on server.';
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// PAGE RENDERING
// ─────────────────────────────────────────────────────────────────────────────

// SECURITY: Do NOT reveal the real filename in the page title before access is granted.
if ($fileNotFound) {
    $pageTitle = 'Not found';
} elseif (!$accessGranted) {
    // File is locked — show a generic title; do not expose the real filename.
    $pageTitle = 'Protected file';
} else {
    $pageTitle = htmlspecialchars($file['original_name']);
}

render_head($pageTitle, false, '../css/style.css');
echo '<div class="card auth-card download-card">';

if ($fileNotFound) {
    echo '<div class="auth-header">
            <div class="logo-mark">⚠️</div>
            <h1>File not found</h1>
            <p>This link is invalid or removed.</p>
          </div>';

} elseif ($fatalError) {
    echo '<div class="auth-header">
            <div class="logo-mark">⚠️</div>
            <h1>Error</h1>
          </div>';
    render_alerts([$fatalError]);

} elseif (!$accessGranted) {
    // ── PASSWORD FORM ─────────────────────────────────────────────────────────
    // SECURITY: Show ONLY the password form. No filename, no file type, no size,
    // no preview. Nothing about the file is revealed until the password is correct.
    // render_modal() with isOpen:true renders the password form inline on the page.
    echo '<div class="auth-header">
            <div class="logo-mark">🔐</div>
            <h1>Protected file</h1>
            <p>Enter the password to access this file.</p>
          </div>';
    render_modal([
        'token'      => $token,
        'filename'   => '',           // SECURITY: do NOT pass the real filename here.
        'verifyUrl'  => 'verify.php',
        'successUrl' => '?token={token}',   // After unlock → preview page (no direct download yet).
        'isOpen'     => true,
    ]);

} else {
    // ── ACCESS GRANTED: PREVIEW + DOWNLOAD BUTTON ─────────────────────────────
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
        // Only show thumbnail after password is verified.
        echo '<img src="thumbnail.php?token=' . htmlspecialchars($token) . '" alt=""
                   style="width:100%; border-radius: var(--radius-md); margin-bottom: 1.25rem; display:block;">';
    } else {
        echo '<div class="alert" style="background: var(--bg-surface); border-color: var(--border);
                   color: var(--text-secondary); margin-bottom: 1.25rem;">'
           . htmlspecialchars($ext) . ' file ready.</div>';
    }

    // Download button — for password-protected files this opens the password modal
    // via the existing action-btn handler in app.js (same pattern as the dashboard).
    // successUrl uses {token} placeholder — JS replaces it at submit time.
    if (!empty($file['password'])) {
        render_modal([
            'token'      => $token,
            'filename'   => $file['original_name'],
            'verifyUrl'  => 'verify.php',
            'successUrl' => '?token={token}&download=1',
            'isOpen'     => false,
        ]);
        echo '<button class="btn btn-primary btn-full action-btn"
                      data-token="'    . htmlspecialchars($token)                . '"
                      data-filename="' . htmlspecialchars($file['original_name']) . '"
                      data-action="download">Download Securely</button>';
    } else {
        // No password set — direct download link is fine.
        echo '<a href="?token=' . htmlspecialchars($token) . '&amp;download=1"
                 class="btn btn-primary btn-full">Download Securely</a>';
    }
}

echo '</div>';
render_foot(false, '../js/app.js');