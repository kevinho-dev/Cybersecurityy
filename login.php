<?php
session_start();

if (isset($_SESSION['user_id'])) {
    header("Location: index.php");
    exit;
}

$error = "";

if (isset($_POST['login'])) {
    $conn = new PDO("mysql:host=localhost;dbname=cybersecurity", "root", "");
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    $username = trim($_POST['username']);
    $password = $_POST['password'];

    $stmt = $conn->prepare("SELECT id, password FROM users WHERE username = ?");
    $stmt->execute([$username]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($user && password_verify($password, $user['password'])) {
        $_SESSION['user_id'] = $user['id'];
        header("Location: index.php");
        exit;
    } else {
        $error = "Ongeldige gebruikersnaam of wachtwoord.";
    }
}
?>
<!DOCTYPE html>
<html lang="nl">
<head>
    <meta charset="UTF-8">
    <title>Inloggen</title>
</head>
<body>
    <h1>Inloggen</h1>
    <?php if ($error): ?><p style="color:red"><?= htmlspecialchars($error) ?></p><?php endif; ?>
    
    <form method="post">
        <input type="text" name="username" placeholder="Gebruikersnaam" required><br><br>
        <input type="password" name="password" placeholder="Wachtwoord" required><br><br>
        <input type="submit" value="Inloggen" name="login">
    </form>
    <br>
    <p>Nog geen account? <a href="register.php">Registreer hier</a>.</p>
</body>
</html>