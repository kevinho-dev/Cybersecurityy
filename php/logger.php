<?php
/**
 * logger.php — central logging helper.
 * Every important event (upload, download, login attempt) is written
 * to the `logs` table so it can be reviewed later via logs.php.
 *
 * event_type values used in this app:
 *   upload, download, login_success, login_failed, unlock_failed
 */

function logEvent(PDO $conn, string $eventType, ?int $userId = null, ?string $username = null, ?string $fileName = null, ?string $details = null): void
{
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';

    $stmt = $conn->prepare(
        "INSERT INTO logs (event_type, username, user_id, file_name, ip_address, details)
         VALUES (?, ?, ?, ?, ?, ?)"
    );
    $stmt->execute([$eventType, $username, $userId, $fileName, $ip, $details]);
}