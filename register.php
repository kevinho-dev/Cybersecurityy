<?php
session_start();

// Redirect logged-in users away from registration
if (isset($_SESSION['user_id'])) {
    header("Location: index.php");
    exit;
}

$error = $success = "";

if (isset($_POST['register'])) {
    $conn = new PDO("mysql:host=localhost;dbname=cybersecurity", "root", "");
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    $username = trim($_POST['username']);
    $password = $_POST['password'];
    $confirmPassword = $_POST['confirm_password'];

    if (empty($username) || empty($password)) {
        $error = "Vul alle velden in.";
    } elseif ($password !== $confirmPassword) {
        $error = "Wachtwoorden komen niet overeen.";
    } elseif (strlen($password) < 8) {
        $error = "Wachtwoord moet minimaal 8 tekens lang zijn.";
    } else {
        // Check if username already exists
        $stmt = $conn->prepare("SELECT id FROM users WHERE username = ?");
        $stmt->execute([$username]);
        if ($stmt->fetch()) {
            $error = "Deze gebruikersnaam is al bezet.";
        } else {
            // Securely hash the password
            $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

            // Insert new user
            $stmt = $conn->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
            $stmt->execute([$username, $hashedPassword]);

            $success = "Account succesvol aangemaakt! Je kunt nu inloggen.";
        }
    }
}
?>
<!DOCTYPE html>
<html lang="nl">
<head>
    <meta charset="UTF-8">
    <title>Registreren</title>
</head>
<body>
    <h1>Registreren</h1>
    <?php if ($error): ?><p style="color:red"><?= htmlspecialchars($error) ?></p><?php endif; ?>
    <?php if ($success): ?><p style="color:green"><?= htmlspecialchars($success) ?></p><?php endif; ?>
    
    <form method="post">
        <input type="text" name="username" placeholder="Gebruikersnaam" required><br><br>
        <input type="password" name="password" placeholder="Wachtwoord (min. 8 tekens)" required><br><br>
        <input type="password" name="confirm_password" placeholder="Wachtwoord herhalen" required><br><br>
        <input type="submit" value="Registreren" name="register">
    </form>
    <br>
    <p>Heb je al een account? <a href="login.php">Log hier in</a>.</p>
</body>
</html>