<?php
require_once 'config.php';

if (isset($_SESSION['user_id'])) {
    header("Location: index.php");
    exit;
}

$error = "";

if (isset($_POST['login'])) {
    $username = trim($_POST['username']);
    $password = $_POST['password'];

    // Prepared statement om SQL-injection te voorkomen
    $stmt = $conn->prepare("SELECT id, password FROM users WHERE username = ?");
    $stmt->execute([$username]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    // Controleer of de gebruiker bestaat en het wachtwoord klopt met de opgeslagen hash
    if ($user && password_verify($password, $user['password'])) {
        
        // REGEL 1: Vernieuw de sessie-ID na een succesvolle login.
        // Dit vernietigt de oude ID en stopt Session Fixation aanvallen.
        session_regenerate_id(true);

        $_SESSION['user_id'] = $user['id']; // Sla de user_id op in de beveiligde sessie
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
</body>
</html>