<?php
require_once 'config.php';

// Redirect logged-in users away — they already have an account.
require_guest();

$error   = '';
$success = '';
$ip      = $_SERVER['REMOTE_ADDR'] ?? 'unknown';

// Handle the registration form submission.
if (isset($_POST['register'])) {

    // Verify the CSRF token to block forged form submissions.
    if (!verifyCsrf()) {
        $error = 'Invalid request.';

    // Limit registrations per IP to slow down bot signups (3 attempts per hour).
    } elseif (isRateLimited($conn, 'register_attempt', $ip, 3, 60)) {
        $error = 'Too many registration attempts.';

    } else {
        $username        = trim($_POST['username']);
        $password        = $_POST['password'];
        $confirmPassword = $_POST['confirm_password'];

        // Validate all fields step by step.
        if (!$username || !$password) {
            $error = 'Fill all fields.';

        // Username may only contain letters, numbers, and underscores (3–30 chars).
        // This prevents injection attacks via weird characters.
        } elseif (!preg_match('/^[a-zA-Z0-9_]{3,30}$/', $username)) {
            $error = 'Username must be 3–30 chars (alphanumeric/underscore).';

        } elseif ($password !== $confirmPassword) {
            $error = "Passwords don't match.";

        // Enforce a strong password policy.
        } elseif (
            strlen($password) < 8 ||
            !preg_match('/[a-z]/', $password) ||
            !preg_match('/[A-Z]/', $password) ||
            !preg_match('/[0-9]/', $password)
        ) {
            $error = 'Password must be 8+ chars with uppercase, lowercase, and a number.';

        } else {
            // Check whether the username is already taken.
            $stmt = $conn->prepare("SELECT id FROM users WHERE username = ?");
            $stmt->execute([$username]);

            if ($stmt->fetch()) {
                $error = 'Username already taken.';
            } else {
                // password_hash() uses bcrypt, which is slow by design —
                // this makes stolen password hashes very hard to crack.
                $conn->prepare("INSERT INTO users (username, password) VALUES (?, ?)")
                     ->execute([$username, password_hash($password, PASSWORD_DEFAULT)]);

                $success = 'Account created!';
            }
        }
    }
}

render_head('Register', true, '../css/style.css');
?>
<div class="auth-header">
    <div class="logo-mark">✦</div>
    <h1>Create account</h1>
    <p>Free secure file sharing</p>
</div>

<?php render_alerts([$error], [$success]); ?>

<form method="post">
    <?= csrfField() ?>

    <div class="form-group">
        <label for="username">Username</label>
        <input type="text" id="username" name="username"
               placeholder="Choose a username"
               value="<?= htmlspecialchars($_POST['username'] ?? '') ?>"
               required autocomplete="username"
               minlength="3" maxlength="30" pattern="[a-zA-Z0-9_]{3,30}">
    </div>

    <div class="form-group">
        <label for="password">Password</label>
        <input type="password" id="password" name="password"
               placeholder="Min 8 chars, mixed case + number"
               required autocomplete="new-password" minlength="8">
    </div>

    <div class="form-group">
        <label for="confirm_password">Confirm password</label>
        <input type="password" id="confirm_password" name="confirm_password"
               placeholder="Repeat password"
               required autocomplete="new-password" minlength="8">
    </div>

    <button type="submit" name="register" class="btn btn-primary btn-full">Create account</button>
</form>

<div class="auth-footer">Already have an account? <a href="login.php">Login here</a></div>

<?php render_foot(true, '../js/app.js'); ?>
