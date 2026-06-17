<?php
// Laad de centrale configuratie
require_once 'config.php';

// Toegangscontrole: alleen ingelogde gebruikers mogen downloaden
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit;
}

// Haal de token op uit de URL-balk (indien aanwezig)
$token = $_GET["token"] ?? "";

// Zoek het bijbehorende bestand op in de database via een Prepared Statement
$stmt = $conn->prepare("SELECT * FROM uploads WHERE share_token = ?");
$stmt->execute([$token]);
$file = $stmt->fetch(PDO::FETCH_ASSOC);

// Stop direct als de token niet bestaat in de database
if(!$file) die("Niet gevonden.");

$error = "";
$toegang = false;

// 1. Verwerk de wachtwoord-invoer (POST aanroep)
if(isset($_POST["password"])) {
    if(password_verify($_POST["password"], $file["password"] ?? "")) {
        /**
         * VEILIGE PERSISTENTIE (BUG FIX)
         * Omdat een gewone HTML downloadlink een nieuwe GET-aanroep doet, raakten we voorheen 
         * de $_POST data kwijt en werd de gebruiker opnieuw om een wachtwoord gevraagd. 
         * Dit lossen we veilig op door de goedgekeurde toegang op te slaan in de server-sessie.
         */
        $_SESSION['unlocked_tokens'][$token] = true;
    } else {
        $error = "Verkeerd wachtwoord.";
    }
}

// 2. Evalueer of de gebruiker in deze sessie al eerder succesvol toegang heeft verkregen
if (isset($_SESSION['unlocked_tokens'][$token]) && $_SESSION['unlocked_tokens'][$token] === true) {
    $toegang = true;
}

// Als de gebruiker succesvol is geverifieerd, starten we de bestandscontrole en overdracht
if ($toegang) {
    $path = "uploads/" . $file["stored_name"];
    
    // Controleer of het bestand daadwerkelijk fysiek op de server staat
    if (file_exists($path)) {
        
        /**
         * =========================================================================
         * STAP 3 — INTEGRITEITSCONTROLE BIH DOWNLOAD (NIEUW)
         * =========================================================================
         */
        // 1. Bereken de actuele SHA-256 hash van het fysieke bestand op de server
        $currentHash = hash_file('sha256', $path);
        
        // 2. Haal de opgeslagen hash op uit de database-rij
        // LET OP: Controleer of jouw databasekolom exact 'file_hash' of 'hash' heet en pas dit hieronder aan indien nodig!
        $storedHash = $file['file_hash'] ?? $file['hash'] ?? ''; 
        
        // 3. Vergelijk de twee hashes met elkaar en geef een foutmelding als ze afwijken
        if ($currentHash !== $storedHash) {
            die("Beveiligingswaarschuwing (Stap 3): De integriteitscontrole is mislukt! Het bestand op de server is sinds de upload gewijzigd, gemanipuleerd of beschadigd.");
        }
        /** ========================================================================= */

        /**
         * DIRECT DOWNLOAD ENFORCEMENT
         * We sturen specifieke HTTP-headers mee om de browser te dwingen het bestand te downloaden 
         * in plaats van het uit te voeren. Dit voorkomt dat eventuele verborgen scripts schade aanrichten.
         */
        header("Content-Type: " . $file["mime_type"]);
        header("Content-Disposition: attachment; filename=\"" . $file["original_name"] . "\"");
        header("Content-Length: " . filesize($path));
        
        // Lees het bestand uit en stuur de binaire datastroom rechtstreeks naar de browser
        readfile($path);
        exit;
    } else {
        die("Bestand bevindt zich niet meer op de server.");
    }
}
?>
<!DOCTYPE html>
<html lang="nl">
<head>
    <meta charset="UTF-8">
    <title><?= htmlspecialchars($file["original_name"]) ?></title>
</head>
<body>
<?php if(!$toegang): ?>
    <h1>Wachtwoord vereist</h1>
    <form method="post">
        <input type="password" name="password" placeholder="Wachtwoord" required><br><br>
        <input type="submit" value="Toegang">
    </form>
    <?php if($error): ?><p style="color:red"><?= htmlspecialchars($error) ?></p><?php endif; ?>
<?php endif; ?>
</body>
</html>