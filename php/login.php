<?php
require_once 'config.php';
require_guest();

 $error = ""; $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
 $next = (isset($_GET['next']) && preg_match('#^download\.php\?token=[a-f0-9]{64}$#', urldecode($_GET['next']))) ? urldecode($_GET['next']) : "";

if (isset($_POST['login'])) {
    if (!verifyCsrf()) $error = "Invalid request.";
    elseif (isRateLimited($conn, 'login_failed', $ip)) $error = "Too many failed attempts. Try again in 15 minutes.";
    else {
        $stmt = $conn->prepare("SELECT id, username, password, role FROM users WHERE username = ?");
        $stmt->execute([trim($_POST['username'])]); $user = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($user && password_verify($_POST['password'], $user['password'])) {
            session_regenerate_id(true);
            $_SESSION['user_id'] = $user['id']; $_SESSION['username'] = $user['username']; $_SESSION['role'] = $user['role'];
            logEvent($conn, 'login_success', $user['id'], $user['username']);
            header("Location: " . (preg_match('#^download\.php\?token=[a-f0-9]{64}$#', $_POST['next'] ?? '') ? $_POST['next'] : "../index.php")); exit;
        } else {
            $error = "Invalid username or password.";
            logEvent($conn, 'login_failed', null, trim($_POST['username']));
        }
    }
}

render_head('Login', true, '../css/style.css');
?>
    <div class="auth-header"><div class="logo-mark">🔒</div><h1>Welcome back</h1><p><?= !empty($next) ? 'Login to access your file' : 'Login to manage your files' ?></p></div>
    <?= render_alerts([$error]) ?>
    <form method="post"><?= csrfField() ?><input type="hidden" name="next" value="<?= htmlspecialchars($next) ?>">
        <div class="form-group"><label for="username">Username</label><input type="text" id="username" name="username" placeholder="Enter your username" value="<?= htmlspecialchars($_POST['username'] ?? '') ?>" required autocomplete="username"></div>
        <div class="form-group"><label for="password">Password</label><input type="password" id="password" name="password" placeholder="Enter your password" required autocomplete="current-password"></div>
        <button type="submit" name="login" class="btn btn-primary btn-full">Login</button>
    </form>
    <div class="auth-footer">No account? <a href="register.php">Register here</a></div>
<?php render_foot(true, '../js/app.js'); ?>