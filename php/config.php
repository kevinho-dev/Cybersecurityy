<?php
/**
 * config.php — Core initialization: Headers, Sessions, CSRF, Rate Limiting, DB
 */
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: strict-origin-when-cross-origin');
header("Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com;");

ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_samesite', 'Lax');
if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ini_set('session.cookie_secure', 1);
session_start();

// CSRF
if (empty($_SESSION['csrf_token'])) $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
function csrfField(): string { return '<input type="hidden" name="csrf_token" value="' . htmlspecialchars($_SESSION['csrf_token']) . '">'; }
function verifyCsrf(): bool { return isset($_POST['csrf_token']) && hash_equals($_SESSION['csrf_token'], $_POST['csrf_token']); }
function csrfMetaTag(): string { return '<meta name="csrf-token" content="' . htmlspecialchars($_SESSION['csrf_token']) . '">'; }

// Rate Limiting
function isRateLimited(PDO $conn, string $event, string $ip, int $max = 5, int $min = 15): bool {
    $stmt = $conn->prepare("SELECT COUNT(*) FROM logs WHERE ip_address = ? AND event_type = ? AND created_at > DATE_SUB(NOW(), INTERVAL ? MINUTE)");
    $stmt->execute([$ip, $event, $min]);
    return $stmt->fetchColumn() >= $max;
}

// Database
try {
    $conn = new PDO("mysql:host=localhost;dbname=cybersecurity", "root", "");
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) { die("Database error."); }

 $conn->exec("CREATE TABLE IF NOT EXISTS logs (
    id INT AUTO_INCREMENT PRIMARY KEY, event_type VARCHAR(30) NOT NULL, username VARCHAR(255) NULL,
    user_id INT NULL, file_name VARCHAR(255) NULL, ip_address VARCHAR(45) NULL, details VARCHAR(255) NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, INDEX idx_event (event_type), INDEX idx_ip (ip_address, created_at)
)");
try { $conn->exec("ALTER TABLE users ADD COLUMN role VARCHAR(20) NOT NULL DEFAULT 'user'"); } catch (PDOException $e) {}

require_once __DIR__ . '/helpers.php';
require_once __DIR__ . '/logger.php';