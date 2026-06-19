<?php
/**
 * login.php — user login
 * Supports an optional ?next= query parameter so visitors who were
 * redirected here from download.php (because they weren't logged in)
 * are sent back to the correct download URL after authenticating.
 */
require_once 'config.php';

if (isset($_SESSION['user_id'])) {
    header("Location: ../index.php");
    exit;
}

$error = "";

// Sanitise the ?next= value — only allow relative paths inside this app
$next = "";
if (!empty($_GET['next'])) {
    $decoded = urldecode($_GET['next']);
    // Only allow paths that start with download.php (no open-redirect)
    if (strpos($decoded, 'download.php') === 0) {
        $next = $decoded;
    }
}

if (isset($_POST['login'])) {
    $username = trim($_POST['username']);
    $password = $_POST['password'];
    $next     = $_POST['next'] ?? "";

    // Prepared statement prevents SQL injection
    $stmt = $conn->prepare("SELECT id, username, password, role FROM users WHERE username = ?");
    $stmt->execute([$username]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    // password_verify: timing-safe bcrypt check
    if ($user && password_verify($password, $user['password'])) {
        // Regenerate session ID after login to prevent session fixation attacks
        session_regenerate_id(true);
        $_SESSION['user_id']  = $user['id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['role']     = $user['role'];
        logEvent($conn, 'login_success', $user['id'], $username);

        // Redirect back to the download page the visitor originally wanted, or dashboard
        if (!empty($next) && strpos($next, 'download.php') === 0) {
            header("Location: " . $next);
        } else {
            header("Location: ../index.php");
        }
        exit;
    } else {
        // Vague error on purpose: stops attackers finding out which usernames exist
        $error = "Invalid username or password.";
        logEvent($conn, 'login_failed', null, $username, null, 'Wrong username or password');
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login — kevinstopmettelaatkomen</title>
    <link rel="stylesheet" href="../css/style.css">
</head>
<body>

<div class="auth-page">
    <div class="card auth-card">
        <div class="auth-header">
            <div class="logo-mark">🔒</div>
            <h1>Welcome back</h1>
            <?php if (!empty($next)): ?>
                <p>Login to access your file</p>
            <?php else: ?>
                <p>Login to manage your files</p>
            <?php endif; ?>
        </div>

        <?php if ($error): ?>
            <div class="alert alert-danger"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>

        <form method="post">
            <!-- Carry the ?next= value through the form so the redirect survives POST -->
            <input type="hidden" name="next" value="<?= htmlspecialchars($next) ?>">

            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username"
                       placeholder="Enter your username"
                       value="<?= htmlspecialchars($_POST['username'] ?? '') ?>"
                       required autocomplete="username">
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password"
                       placeholder="Enter your password"
                       required autocomplete="current-password">
            </div>
            <button type="submit" name="login" class="btn btn-primary btn-full">Login</button>
        </form>

        <div class="auth-footer">
            No account? <a href="register.php">Register here</a>
        </div>
    </div>
</div>

</body>
</html>
