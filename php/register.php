<?php
/**
 * register.php — new user registration
 */
require_once 'config.php';

if (isset($_SESSION['user_id'])) {
    header("Location: ../index.php");
    exit;
}

$error = $success = "";

if (isset($_POST['register'])) {
    $username        = trim($_POST['username']);
    $password        = $_POST['password'];
    $confirmPassword = $_POST['confirm_password'];

    if (empty($username) || empty($password)) {
        $error = "Fill all fields.";
    } elseif ($password !== $confirmPassword) {
        $error = "Passwords don't match.";
    } elseif (strlen($password) < 8) {
        $error = "Password must be 8+ characters.";
    } else {
        // Check if username is already taken
        $stmt = $conn->prepare("SELECT id FROM users WHERE username = ?");
        $stmt->execute([$username]);

        if ($stmt->fetch()) {
            $error = "Username already taken.";
        } else {
            // bcrypt: auto-generates a salt and is slow on purpose (slows brute-force)
            $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

            $stmt = $conn->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
            $stmt->execute([$username, $hashedPassword]);

            $success = "Account created! You can now login.";
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register — kevinstopmettelaatkomen</title>
    <link rel="stylesheet" href="../css/style.css">
</head>
<body>

<div class="auth-page">
    <div class="card auth-card">
        <div class="auth-header">
            <div class="logo-mark">✦</div>
            <h1>Create account</h1>
            <p>Free secure file sharing</p>
        </div>

        <?php if ($error): ?>
            <div class="alert alert-danger"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>
        <?php if ($success): ?>
            <div class="alert alert-success"><?= htmlspecialchars($success) ?></div>
        <?php endif; ?>

        <form method="post">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username"
                       placeholder="Choose a username"
                       value="<?= htmlspecialchars($_POST['username'] ?? '') ?>"
                       required autocomplete="username">
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password"
                       placeholder="Min 8 characters"
                       required autocomplete="new-password">
            </div>
            <div class="form-group">
                <label for="confirm_password">Confirm password</label>
                <input type="password" id="confirm_password" name="confirm_password"
                       placeholder="Repeat password"
                       required autocomplete="new-password">
            </div>
            <button type="submit" name="register" class="btn btn-primary btn-full">Create account</button>
        </form>

        <div class="auth-footer">
            Already have an account? <a href="login.php">Login here</a>
        </div>
    </div>
</div>

</body>
</html>