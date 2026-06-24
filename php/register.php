<?php
require_once 'config.php';
require_guest();

 $error = $success = ""; $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';

if (isset($_POST['register'])) {
    if (!verifyCsrf()) $error = "Invalid request.";
    elseif (isRateLimited($conn, 'register_attempt', $ip, 3, 60)) $error = "Too many registration attempts.";
    else {
        $user = trim($_POST['username']); $pass = $_POST['password']; $confirm = $_POST['confirm_password'];
        if (!$user || !$pass) $error = "Fill all fields.";
        elseif (!preg_match('/^[a-zA-Z0-9_]{3,30}$/', $user)) $error = "Username must be 3-30 chars (alphanumeric/underscore).";
        elseif ($pass !== $confirm) $error = "Passwords don't match.";
        elseif (strlen($pass) < 8 || !preg_match('/[a-z]/', $pass) || !preg_match('/[A-Z]/', $pass) || !preg_match('/[0-9]/', $pass)) $error = "Password must be 8+ chars with uppercase, lowercase, and a number.";
        else {
            $stmt = $conn->prepare("SELECT id FROM users WHERE username = ?"); $stmt->execute([$user]);
            if ($stmt->fetch()) $error = "Username already taken.";
            else { $conn->prepare("INSERT INTO users (username, password) VALUES (?, ?)")->execute([$user, password_hash($pass, PASSWORD_DEFAULT)]); $success = "Account created!"; }
        }
    }
}

render_head('Register', true, '../css/style.css');
?>
    <div class="auth-header"><div class="logo-mark">✦</div><h1>Create account</h1><p>Free secure file sharing</p></div>
    <?= render_alerts([$error], [$success]) ?>
    <form method="post"><?= csrfField() ?>
        <div class="form-group"><label for="username">Username</label><input type="text" id="username" name="username" placeholder="Choose a username" value="<?= htmlspecialchars($_POST['username'] ?? '') ?>" required autocomplete="username" minlength="3" maxlength="30" pattern="[a-zA-Z0-9_]{3,30}"></div>
        <div class="form-group"><label for="password">Password</label><input type="password" id="password" name="password" placeholder="Min 8 chars, mixed case + number" required autocomplete="new-password" minlength="8"></div>
        <div class="form-group"><label for="confirm_password">Confirm password</label><input type="password" id="confirm_password" name="confirm_password" placeholder="Repeat password" required autocomplete="new-password" minlength="8"></div>
        <button type="submit" name="register" class="btn btn-primary btn-full">Create account</button>
    </form>
    <div class="auth-footer">Already have an account? <a href="login.php">Login here</a></div>
<?php render_foot(true, '../js/app.js'); ?>