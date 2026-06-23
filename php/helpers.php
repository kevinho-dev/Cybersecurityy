<?php
/** helpers.php — DRY HTML rendering & Auth checks */

function require_auth(string $redirect = 'php/login.php'): void {
    if (!isset($_SESSION['user_id'])) { header("Location: $redirect"); exit; }
}
function require_guest(string $redirect = '../index.php'): void {
    if (isset($_SESSION['user_id'])) { header("Location: $redirect"); exit; }
}
function get_image_mimes(): array {
    return ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
}
function render_alerts(array $errors = [], array $successes = []): void {
    foreach ($errors as $msg) echo '<div class="alert alert-danger">' . htmlspecialchars($msg) . '</div>';
    foreach ($successes as $msg) echo '<div class="alert alert-success">' . htmlspecialchars($msg) . '</div>';
}

function render_head(string $title, bool $isAuth = false, string $css = 'css/style.css'): void {
    echo '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">';
    echo '<title>' . htmlspecialchars($title) . ' — kevinstopmettelaatkomen</title>' . csrfMetaTag();
    echo '<link rel="stylesheet" href="' . htmlspecialchars($css) . '"></head><body>';
    if ($isAuth) echo '<div class="auth-page"><div class="card auth-card">';
    else echo '<nav class="topbar"><span class="brand">kevinstopmettelaatkomen</span><a href="php/logs.php" class="logout-link">Activity log</a><a href="php/logout.php" class="logout-link">Logout</a></nav><div class="page-wrapper">';
}

function render_foot(bool $isAuth = false, string $js = 'js/app.js'): void {
    if ($isAuth) echo '</div></div>';
    else echo '</div>';
    echo '<script src="' . htmlspecialchars($js) . '"></script></body></html>';
}

/** Generates the single, unified password modal used by both dashboard and download pages */
function render_modal(array $data = []): void {
    $token = htmlspecialchars($data['token'] ?? '');
    $filename = htmlspecialchars($data['filename'] ?? '');
    $action = htmlspecialchars($data['action'] ?? 'download');
    $verifyUrl = htmlspecialchars($data['verifyUrl'] ?? 'php/verify.php');
    $successUrl = htmlspecialchars($data['successUrl'] ?? 'php/download.php?token={token}&direct=1');
    $isOpen = !empty($data['isOpen']) ? 'flex' : 'none';

    echo '<div id="passwordModal" class="modal-overlay" style="display:' . $isOpen . ';" 
        data-token="'.$token.'" data-action="'.$action.'" data-verify-url="'.$verifyUrl.'" data-success-url="'.$successUrl.'">
        <div class="modal-card">
            <div class="modal-header"><span class="modal-title">🔐 Enter password</span><button class="modal-close" id="modalClose">&times;</button></div>
            <form id="passwordForm">
                <p style="margin-bottom: 1rem;">The file <strong id="modalFilename">'.$filename.'</strong> is password‑protected.</p>
                <div class="form-group"><label for="modalPassword">Password</label><input type="password" id="modalPassword" name="password" placeholder="Enter download password" required ' . ($isOpen === 'flex' ? 'autofocus' : '') . '></div>
                <button type="submit" class="btn btn-primary btn-full">Unlock</button>
            </form>
            <div id="modalError" class="alert alert-danger" style="display:none; margin-top: 1rem;"></div>
        </div>
    </div>';
}