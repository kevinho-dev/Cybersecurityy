<?php
require_once 'config.php';

// Redirect logged-in users away — they don't need to see the login page.
require_guest();

$error = '';
$ip    = $_SERVER['REMOTE_ADDR'] ?? 'unknown';

// We allow a ?next= redirect parameter, but ONLY for the download flow.
// This prevents "open redirect" attacks where a malicious link sends users
// to an attacker's site after login. We only accept tokens we recognise.
$next = '';
if (isset($_GET['next'])) {
    $decoded = urldecode($_GET['next']);
    // Only accept a URL that looks exactly like "download.php?token=<64 hex chars>"
    if (preg_match('#^download\.php\?token=[a-f0-9]{64}$#', $decoded)) {
        $next = $decoded;
    }
}

// Handle the login form submission.
if (isset($_POST['login'])) {

    // Verify the CSRF token to block forged form submissions from other websites.
    if (!verifyCsrf()) {
        $error = 'Invalid request.';

    // Block the IP if it has failed too many times recently (brute-force protection).
    } elseif (isRateLimited($conn, 'login_failed', $ip)) {
        $error = 'Too many failed attempts. Try again in 15 minutes.';

    } else {
        // Look up the user by username. We use a prepared statement to prevent SQL injection.
        $stmt = $conn->prepare("SELECT id, username, password, role FROM users WHERE username = ?");
        $stmt->execute([trim($_POST['username'])]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        // password_verify() safely compares the submitted password against the stored hash.
        if ($user && password_verify($_POST['password'], $user['password'])) {
            // Regenerate the session ID after login to prevent "session fixation" attacks,
            // where an attacker plants a known session ID before the user logs in.
            session_regenerate_id(true);

            // Store the user's identity in the session so other pages can read it.
            $_SESSION['user_id']  = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['role']     = $user['role'];

            logEvent($conn, 'login_success', $user['id'], $user['username']);

            // Only redirect to ?next= if it matches our safe pattern.
            $postNext = $_POST['next'] ?? '';
            $redirect = preg_match('#^download\.php\?token=[a-f0-9]{64}$#', $postNext)
                ? $postNext
                : '../index.php';

            header("Location: $redirect");
            exit;
        }

        // Use a vague error message — don't tell the attacker whether the username exists.
        $error = 'Invalid username or password.';

        // Log the failure. We record the attempted username even though user_id is unknown.
        logEvent($conn, 'login_failed', null, trim($_POST['username']));
    }
}

render_head('Login', true, '../css/style.css');
?>
<div class="auth-header">
    <div class="logo-mark">🔒</div>
    <h1>Welcome back</h1>
    <p><?= !empty($next) ? 'Login to access your file' : 'Login to manage your files' ?></p>
</div>

<?php render_alerts([$error]); ?>

<form method="post">
    <?= csrfField() ?>
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

<div class="auth-footer">No account? <a href="register.php">Register here</a></div>

<?php render_foot(true, '../js/app.js'); ?>
