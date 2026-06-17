<?php
// Laad de centrale configuratie (sessies, databaseverbinding en security-headers)
require_once 'config.php';

// Als de gebruiker al is ingelogd, sturen we hem direct door naar het dashboard.
if (isset($_SESSION['user_id'])) {
    header("Location: index.php");
    exit;
}

$error = "";

// Controleer of het inlogformulier is verstuurd
if (isset($_POST['login'])) {
    // Verwijder onnodige spaties aan het begin en einde van de gebruikersnaam
    $username = trim($_POST['username']);
    $password = $_POST['password'];

    // Gebruik een Prepared Statement om SQL-injectie te voorkomen
    $stmt = $conn->prepare("SELECT id, password FROM users WHERE username = ?");
    $stmt->execute([$username]);
    // Haal de resultaten op als een associatieve array
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    // Controleer of de gebruiker bestaat en of het ingevoerde wachtwoord matcht met de bcrypt-hash
    if ($user && password_verify($password, $user['password'])) {
        
        /**
         * CROCIAAL VOOR CYBERSECURITY: SESSIE REGENERATIE
         * Door de sessie-ID direct na een succesvolle login te vernieuwen, maken we 
         * Session Fixation aanvallen onmogelijk. Een hacker kan nu niet meer een vooraf 
         * gekaapte sessie-ID blijven gebruiken.
         */
        session_regenerate_id(true);

        // Sla het unieke gebruikers-ID op in de beveiligde server-side sessie
        $_SESSION['user_id'] = $user['id'];
        
        // Stuur de gebruiker door naar de beveiligde index-pagina
        header("Location: index.php");
        exit;
    } else {
        // Beveiligingstip: Geef een generieke foutmelding. Vertel de aanvaller niet 
        // of de gebruikersnaam of het wachtwoord fout was om 'user enumeration' te voorkomen.
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