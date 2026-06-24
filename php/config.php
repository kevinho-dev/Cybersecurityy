<?php
/**
 * config.php — Loaded first on every page.
 *
 * This file does four things in order:
 *   1. Sends security headers to the browser.
 *   2. Hardens the session cookie and starts the session.
 *   3. Sets up CSRF protection (anti-forgery tokens).
 *   4. Connects to the database.
 *
 * After this file runs, every other file in the project can use
 * $conn (the database connection) and all the helper functions below.
 */

// ─────────────────────────────────────────────────────────────────────────────
// 1. SECURITY HEADERS
// These tell the browser how to behave safely when loading our pages.
// ─────────────────────────────────────────────────────────────────────────────

// Prevent our page from being loaded inside an <iframe> on another site.
// This stops "clickjacking" attacks where a hidden iframe tricks users.
header('X-Frame-Options: DENY');

// Tell the browser not to guess the file type — trust what we say it is.
// Without this, a browser might run a text file as JavaScript.
header('X-Content-Type-Options: nosniff');

// Old XSS filter for legacy browsers — modern browsers ignore this.
header('X-XSS-Protection: 1; mode=block');

// Only send the full referrer URL to our own site; other sites only get the origin.
header('Referrer-Policy: strict-origin-when-cross-origin');

// Content Security Policy: define exactly where scripts, styles, and fonts may load from.
// 'self' means "only from our own domain". We allow Google Fonts as an exception.
header("Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com;");


// ─────────────────────────────────────────────────────────────────────────────
// 2. SESSION HARDENING
// PHP sessions identify a logged-in user via a cookie. We make that cookie
// as hard to steal as possible.
// ─────────────────────────────────────────────────────────────────────────────

// HttpOnly: JavaScript cannot read this cookie. Protects against XSS theft.
ini_set('session.cookie_httponly', 1);

// SameSite=Lax: the browser won't send this cookie with cross-site requests.
// This helps prevent CSRF attacks (covered further below).
ini_set('session.cookie_samesite', 'Lax');

// Secure flag: only send the cookie over HTTPS, not plain HTTP.
// We skip this on localhost so local development still works.
if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
    ini_set('session.cookie_secure', 1);
}

session_start();


// ─────────────────────────────────────────────────────────────────────────────
// 3. CSRF PROTECTION
//
// CSRF (Cross-Site Request Forgery) is when another website tricks a logged-in
// user's browser into submitting a form to our site without the user knowing.
//
// We stop this by generating a secret random token for each session.
// Every form includes this token as a hidden field. When the form is submitted,
// we check that the token matches. An attacker on another site cannot read
// our token, so their forged request will fail.
// ─────────────────────────────────────────────────────────────────────────────

// Generate a token the first time a session is created.
// bin2hex(random_bytes(32)) creates a secure 64-character hex string.
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

/**
 * Returns an HTML hidden input containing the CSRF token.
 * Paste <?= csrfField() ?> inside every <form> that changes data.
 */
function csrfField(): string
{
    return '<input type="hidden" name="csrf_token" value="'
         . htmlspecialchars($_SESSION['csrf_token']) . '">';
}

/**
 * Returns an HTML <meta> tag with the CSRF token.
 * JavaScript reads this to include the token in fetch() calls.
 */
function csrfMetaTag(): string
{
    return '<meta name="csrf-token" content="'
         . htmlspecialchars($_SESSION['csrf_token']) . '">';
}

/**
 * Checks that the submitted CSRF token matches the one stored in the session.
 *
 * hash_equals() is used instead of === to prevent timing attacks:
 * a normal string comparison can leak information about the token length
 * by returning faster when strings differ early. hash_equals() always
 * takes the same amount of time regardless of where strings differ.
 */
function verifyCsrf(): bool
{
    return isset($_POST['csrf_token'])
        && hash_equals($_SESSION['csrf_token'], $_POST['csrf_token']);
}


// ─────────────────────────────────────────────────────────────────────────────
// 4. RATE LIMITING
//
// Rate limiting stops brute-force attacks: if someone tries to guess a password
// by submitting the form hundreds of times, we block them after a few failures.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Returns true if the given IP address has triggered the given event
 * too many times recently.
 *
 * For example: isRateLimited($conn, 'login_failed', '1.2.3.4', 5, 15)
 * returns true if IP 1.2.3.4 failed to log in 5 or more times in the last 15 minutes.
 *
 * We reuse the existing logs table for this — no extra database table needed.
 */
function isRateLimited(PDO $conn, string $event, string $ip, int $max = 5, int $minutes = 15): bool
{
    $stmt = $conn->prepare(
        "SELECT COUNT(*) FROM logs
         WHERE ip_address = ?
           AND event_type = ?
           AND created_at > DATE_SUB(NOW(), INTERVAL ? MINUTE)"
    );
    $stmt->execute([$ip, $event, $minutes]);
    return (int) $stmt->fetchColumn() >= $max;
}


// ─────────────────────────────────────────────────────────────────────────────
// 5. DATABASE CONNECTION
// ─────────────────────────────────────────────────────────────────────────────

try {
    $conn = new PDO("mysql:host=localhost;dbname=cybersecurity", "root", "");
    // Make PDO throw exceptions on errors instead of silently failing.
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    // Never show the real error — it might expose database credentials or table names.
    die("Database error.");
}


// ─────────────────────────────────────────────────────────────────────────────
// 6. DATABASE SCHEMA SETUP
//
// CREATE TABLE IF NOT EXISTS is safe to run every page load — it does nothing
// if the table already exists.
// ─────────────────────────────────────────────────────────────────────────────

$conn->exec("
    CREATE TABLE IF NOT EXISTS logs (
        id          INT AUTO_INCREMENT PRIMARY KEY,
        event_type  VARCHAR(30)  NOT NULL,
        username    VARCHAR(255) NULL,
        user_id     INT          NULL,
        file_name   VARCHAR(255) NULL,
        ip_address  VARCHAR(45)  NULL,
        details     VARCHAR(255) NULL,
        created_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_event (event_type),
        INDEX idx_ip    (ip_address, created_at)
    )
");

// Add the 'role' column to users if it doesn't exist yet.
// ALTER TABLE fails if the column already exists, so we catch that error
// and ignore it — it just means the migration already ran before.
try {
    $conn->exec("ALTER TABLE users ADD COLUMN role VARCHAR(20) NOT NULL DEFAULT 'user'");
} catch (PDOException $e) {
    // Column already exists — this is expected on every run after the first.
}


// Load the shared helper functions and the audit logger.
require_once __DIR__ . '/helpers.php';
require_once __DIR__ . '/logger.php';
