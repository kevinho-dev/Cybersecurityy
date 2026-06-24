<?php
/**
 * logger.php — Records security-relevant events to the database.
 *
 * Every important action (login, upload, download, failed attempts) should
 * be logged here so an admin can review them later in logs.php.
 *
 * Think of this as a security camera for the application.
 */

/**
 * Saves one audit event to the logs table.
 *
 * @param PDO         $conn      The database connection from config.php.
 * @param string      $eventType A short machine-readable label, e.g. 'login_failed'.
 * @param int|null    $userId    The logged-in user's ID, or null if the user is unknown
 *                               (for example, a failed login attempt where we don't know who it is).
 * @param string|null $username  The username involved (stored separately from user_id so
 *                               we can log the attempted name even on a failed login).
 * @param string|null $fileName  The file involved, if any.
 * @param string|null $details   Any extra context worth saving.
 */
function logEvent(
    PDO     $conn,
    string  $eventType,
    ?int    $userId   = null,
    ?string $username = null,
    ?string $fileName = null,
    ?string $details  = null
): void {
    // $_SERVER['REMOTE_ADDR'] is the IP address of whoever made the request.
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';

    $stmt = $conn->prepare(
        "INSERT INTO logs (event_type, username, user_id, file_name, ip_address, details)
         VALUES (?, ?, ?, ?, ?, ?)"
    );
    $stmt->execute([$eventType, $username, $userId, $fileName, $ip, $details]);
}
