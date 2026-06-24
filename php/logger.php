<?php
function logEvent(PDO $conn, string $eventType, ?int $userId = null, ?string $username = null, ?string $fileName = null, ?string $details = null): void {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $stmt = $conn->prepare("INSERT INTO logs (event_type, username, user_id, file_name, ip_address, details) VALUES (?, ?, ?, ?, ?, ?)");
    $stmt->execute([$eventType, $username, $userId, $fileName, $ip, $details]);
}