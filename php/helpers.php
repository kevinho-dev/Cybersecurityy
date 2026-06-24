<?php
/**
 * helpers.php — Reusable functions used across multiple pages.
 *
 * Contains:
 *   - Auth guards (redirect users who shouldn't be on a page)
 *   - Small utility functions
 *   - HTML rendering helpers (so we don't repeat the same HTML everywhere)
 */


// ─────────────────────────────────────────────────────────────────────────────
// AUTH GUARDS
// Call these at the top of any page that needs access control.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Kicks unauthenticated visitors to the login page.
 * Call this at the top of any page that requires a logged-in user.
 */
function require_auth(string $redirect = 'php/login.php'): void
{
    if (!isset($_SESSION['user_id'])) {
        header("Location: $redirect");
        exit;
    }
}

/**
 * Kicks already-logged-in users away from auth-only pages (login, register).
 * We don't want a logged-in user accidentally seeing the login form.
 */
function require_guest(string $redirect = '../index.php'): void
{
    if (isset($_SESSION['user_id'])) {
        header("Location: $redirect");
        exit;
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// UTILITY
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Returns the list of image MIME types we accept for uploads and thumbnails.
 * Keeping this in one place means both upload validation and the thumbnail
 * endpoint always agree on what counts as an image.
 */
function get_image_mimes(): array
{
    return ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
}


// ─────────────────────────────────────────────────────────────────────────────
// HTML RENDERING HELPERS
// These functions print reusable chunks of HTML so we don't copy-paste them.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Prints error and/or success alert boxes.
 * htmlspecialchars() converts special characters like < > & into safe HTML
 * entities, preventing XSS (cross-site scripting) attacks.
 */
function render_alerts(array $errors = [], array $successes = []): void
{
    foreach ($errors    as $msg) {
        echo '<div class="alert alert-danger">'  . htmlspecialchars($msg) . '</div>';
    }
    foreach ($successes as $msg) {
        echo '<div class="alert alert-success">' . htmlspecialchars($msg) . '</div>';
    }
}

/**
 * Prints the opening HTML of every page: <head>, navigation bar, and layout wrapper.
 *
 * @param string $title   The page title shown in the browser tab.
 * @param bool   $isAuth  true  → show the centered card layout (login/register pages).
 *                        false → show the top nav bar + page wrapper (all other pages).
 * @param string $css     Path to the stylesheet, relative to the current page.
 */
function render_head(string $title, bool $isAuth = false, string $css = 'css/style.css'): void
{
    echo '<!DOCTYPE html><html lang="en"><head>'
       . '<meta charset="UTF-8">'
       . '<meta name="viewport" content="width=device-width, initial-scale=1.0">'
       . '<title>' . htmlspecialchars($title) . ' — kevinstopmettelaatkomen</title>'
       . csrfMetaTag()
       . '<link rel="stylesheet" href="' . htmlspecialchars($css) . '">'
       . '</head><body>';

    if ($isAuth) {
        // Centered card layout for login and register pages.
        echo '<div class="auth-page"><div class="card auth-card">';
    } else {
        // Regular layout: top nav bar followed by a page content wrapper.
        echo '<nav class="topbar">'
           . '<span class="brand">kevinstopmettelaatkomen</span>'
           . '<a href="php/logs.php" class="logout-link">Activity log</a>'
           . '<a href="php/logout.php" class="logout-link">Logout</a>'
           . '</nav>'
           . '<div class="page-wrapper">';
    }
}

/**
 * Prints the closing HTML of every page: closing layout tags, script tag, </body></html>.
 *
 * @param bool   $isAuth Mirrors the flag passed to render_head().
 * @param string $js     Path to the JavaScript file, relative to the current page.
 */
function render_foot(bool $isAuth = false, string $js = 'js/app.js'): void
{
    // Close the layout div that render_head() opened.
    echo $isAuth ? '</div></div>' : '</div>';
    echo '<script src="' . htmlspecialchars($js) . '"></script></body></html>';
}

/**
 * Prints the password unlock modal (pop-up dialog).
 *
 * This same modal is reused on two pages:
 *   - The dashboard (to unlock before sharing or downloading your own file)
 *   - The public download page (to unlock a password-protected file shared by link)
 *
 * JavaScript in app.js reads the data-* attributes to know what to do on success.
 * The {token} placeholder in successUrl is replaced by JavaScript at runtime.
 *
 * @param array $data {
 *   token:      string  The file's share token.
 *   filename:   string  The filename shown inside the modal.
 *   action:     string  'download' or 'share'.
 *   verifyUrl:  string  The PHP endpoint that checks the password (verify.php).
 *   successUrl: string  Where to go after unlocking; {token} is replaced by JS.
 *   isOpen:     bool    If true, the modal is visible immediately on page load.
 * }
 */
function render_modal(array $data = []): void
{
    // htmlspecialchars() on every value prevents XSS via injected HTML attributes.
    $token      = htmlspecialchars($data['token']      ?? '');
    $filename   = htmlspecialchars($data['filename']   ?? '');
    $action     = htmlspecialchars($data['action']     ?? 'download');
    $verifyUrl  = htmlspecialchars($data['verifyUrl']  ?? 'php/verify.php');
    $successUrl = htmlspecialchars($data['successUrl'] ?? 'php/download.php?token={token}&direct=1');

    // If isOpen is true, show the modal immediately; otherwise hide it.
    $display   = !empty($data['isOpen']) ? 'flex'      : 'none';
    $autofocus = !empty($data['isOpen']) ? 'autofocus' : '';

    echo '
    <div id="passwordModal" class="modal-overlay" style="display:' . $display . ';"
         data-token="'       . $token      . '"
         data-action="'      . $action     . '"
         data-verify-url="'  . $verifyUrl  . '"
         data-success-url="' . $successUrl . '">
        <div class="modal-card">
            <div class="modal-header">
                <span class="modal-title">🔐 Enter password</span>
                <button class="modal-close" id="modalClose">&times;</button>
            </div>
            <form id="passwordForm">
                <p style="margin-bottom: 1rem;">
                    The file <strong id="modalFilename">' . $filename . '</strong> is password&#8209;protected.
                </p>
                <div class="form-group">
                    <label for="modalPassword">Password</label>
                    <input type="password" id="modalPassword" name="password"
                           placeholder="Enter download password" required ' . $autofocus . '>
                </div>
                <button type="submit" class="btn btn-primary btn-full">Unlock</button>
            </form>
            <div id="modalError" class="alert alert-danger" style="display:none; margin-top: 1rem;"></div>
        </div>
    </div>';
}
