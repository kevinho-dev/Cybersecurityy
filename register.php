<?php
// Laad de centrale configuratie
require_once 'config.php';

// Als de gebruiker al ingelogd is, hoeft hij niet te registreren. Direct doorsturen naar index.php.
if (isset($_SESSION['user_id'])) {
    header("Location: index.php");
    exit;
}

$error = $success = "";

// Controleer of het registratieformulier is verstuurd
if (isset($_POST['register'])) {
    $username = trim($_POST['username']);
    $password = $_POST['password'];
    $confirmPassword = $_POST['confirm_password'];

    // Basisvalidaties op de ingevoerde gegevens
    if (empty($username) || empty($password)) {
        $error = "Vul alle velden in.";
    } elseif ($password !== $confirmPassword) {
        $error = "Wachtwoorden komen niet overeen.";
    } elseif (strlen($password) < 8) {
        // Handhaaf een minimaal wachtwoordbeleid voor een betere weerstand tegen brute-force aanvallen
        $error = "Wachtwoord moet minimaal 8 tekens lang zijn.";
    } else {
        // Controleer met een Prepared Statement of de gebruikersnaam al in gebruik is
        $stmt = $conn->prepare("SELECT id FROM users WHERE username = ?");
        $stmt->execute([$username]);
        
        if ($stmt->fetch()) {
            $error = "Deze gebruikersnaam is al bezet.";
        } else {
            /**
             * VEILIGE WACHTWOORD OPSLAG
             * Sla NOOIT wachtwoorden op in platte tekst of onveilige algoritmes zoals MD5/SHA1.
             * PASSWORD_DEFAULT maakt gebruik van bcrypt, wat automatisch een unieke cryptografische 
             * 'salt' toevoegt en computationeel zwaar is (vertraagt brute-force aanvallen).
             */
            $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

            // Voeg de nieuwe gebruiker veilig toe aan de database
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