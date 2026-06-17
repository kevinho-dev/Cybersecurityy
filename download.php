<?php
// Laad de centrale configuratie
require_once 'config.php';

// TOEGANGSCONTROLE: Controleer direct of de gebruiker wel is ingelogd.
// Als de sessie-variabele 'user_id' niet bestaat, sturen we de bezoeker terug naar login.php.
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit;
}

// Haal de token op uit de URL-balk (indien aanwezig)
$token = $_GET["token"] ?? ""; //

// Zoek het bijbehorende bestand op in de database via een Prepared Statement
$stmt = $conn->prepare("SELECT * FROM uploads WHERE share_token = ?"); //
$stmt->execute([$token]); //
$file = $stmt->fetch(PDO::FETCH_ASSOC); //

// Stop direct als de token niet bestaat in de database
if(!$file) die("Niet gevonden."); //

$error = ""; //
$toegang = false; //

// 1. Verwerk de wachtwoord-invoer (POST aanroep)
if(isset($_POST["password"])) { //
    if(password_verify($_POST["password"], $file["password"] ?? "")) { //
        /**
         * VEILIGE PERSISTENTIE (BUG FIX)
         * Omdat een gewone HTML downloadlink een nieuwe GET-aanroep doet, raakten we voorheen 
         * de $_POST data kwijt en werd de gebruiker opnieuw om een wachtwoord gevraagd. 
         * Dit lossen we veilig op door de goedgekeurde toegang op te slaan in de server-sessie.
         */
        $_SESSION['unlocked_tokens'][$token] = true; //
    } else {
        $error = "Verkeerd wachtwoord."; //
    }
}

// 2. Evalueer of de gebruiker in deze sessie al eerder succesvol toegang heeft verkregen
if (isset($_SESSION['unlocked_tokens'][$token]) && $_SESSION['unlocked_tokens'][$token] === true) { //
    $toegang = true; //
}

// 3. Veilige bestandsafhandeling en delivery
if($toegang && isset($_GET["download"])) { //
    $path = "uploads/" . $file["stored_name"]; //
    
    // Controleer of het bestand daadwerkelijk fysiek op de server staat
    if (file_exists($path)) { //
        /**
         * DIRECT DOWNLOAD ENFORCEMENT
         * We sturen specifieke HTTP-headers mee om de browser te dwingen het bestand te downloaden 
         * in plaats van het uit te voeren. Dit voorkomt dat eventuele verborgen scripts schade aanrichten.
         */
        header("Content-Type: " . $file["mime_type"]); //
        header("Content-Disposition: attachment; filename=\"" . $file["original_name"] . "\""); //
        header("Content-Length: " . filesize($path)); //
        
        // Lees het bestand uit en stuur de binaire datastroom rechtstreeks naar de browser
        readfile($path); //
        exit; //
    } else {
        die("Bestand bevindt zich niet meer op de server."); //
    }
}
?>
<!DOCTYPE html>
<html lang="nl">
<head><meta charset="UTF-8"><title><?= htmlspecialchars($file["original_name"]) ?></title></head> <body>
<?php if(!$toegang): ?> <h1>Wachtwoord vereist</h1> <form method="post"> <input type="password" name="password" placeholder="Wachtwoord"> <input type="submit" value="Toegang"> </form> <?php if($error): ?><p style="color:red"><?= htmlspecialchars($error) ?></p><?php endif; ?> <?php else: ?> <h1><?= htmlspecialchars($file["original_name"]) ?></h1> <img src="uploads/<?= htmlspecialchars($file["stored_name"]) ?>" style="max-width:100%"><br><br> <a href="?token=<?= htmlspecialchars($token) ?>&download=1">Download</a> <?php endif; ?> </body>
</html>