<?php
// Laad de centrale configuratie
require_once 'config.php';

// TOEGANGSCONTROLE: Als er geen actieve gebruikerssessie is, sturen we de bezoeker onmiddellijk terug naar login.php
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit;
}

$shareLink = $error = "";

// Als er een deellink is gegenereerd, bouwen we de URL op voor de gebruiker
if(isset($_GET["link"])) {
    // htmlspecialchars voorkomt dat er malafide code in de link-variabele wordt geïnjecteerd
    $shareLink = "http://localhost/cybersecurity/download.php?token=" . htmlspecialchars($_GET["link"]);
}

// Verwerk het upload-formulier zodra de gebruiker op verzenden drukt
if(isset($_POST["submit"])) {
    $file = $_FILES["fileToUpload"];
    
    // Controleer of er daadwerkelijk een bestand is geselecteerd
    if (empty($file["tmp_name"])) {
        $error = "Selecteer een bestand.";
    } else {
        // Haal de bestandsextensie op en zet deze om naar kleine letters
        $ext = strtolower(pathinfo($file["name"], PATHINFO_EXTENSION));

        /**
         * STRIKTE BESTANDSVALIDATIE (FILE UPLOAD SECURITY)
         * Vertrouw nooit blindelings op $_FILES["fileToUpload"]["type"]. Dit kan door een aanvaller worden vervalst.
         */
        if(!getimagesize($file["tmp_name"])) {
            $error = "Geen afbeelding."; // Controleert of de content daadwerkelijk afbeeldingspixels bevat
        } elseif(!in_array($ext, ["jpg","jpeg","png","gif","webp"])) {
            $error = "Verkeerd bestandstype."; // Whitelist-controle om PHP- of HTML-bestanden te blokkeren
        } elseif($file["size"] > 5000000) {
            $error = "Te groot (max 5MB)."; // Voorkomt Denial of Service (DoS) door extreem grote bestanden
        } elseif(empty($_POST["password"])) {
            $error = "Vul een wachtwoord in.";
        } else {
            // Genereer een SHA-256 hash van het fysieke bestand om duplicaten te herkennen
            $hash = hash_file("sha256", $file["tmp_name"]);

            // Controleer of DEZE specifieke ingelogde gebruiker exact dit bestand al eens heeft geüpload
            $stmt = $conn->prepare("SELECT share_token FROM uploads WHERE file_hash = ? AND user_id = ?");
            $stmt->execute([$hash, $_SESSION['user_id']]);
            $existing = $stmt->fetch(PDO::FETCH_ASSOC);

            if($existing) {
                // Als het bestand al bestaat voor deze gebruiker, sturen we hem direct naar de bestaande link
                header("Location: ?link=" . $existing["share_token"]);
                exit;
            } else {
                /**
                 * VEILIGE BESTANDOPSLAG
                 * Sla bestanden NOOIT op onder hun originele naam. Een aanvaller kan een bestand genaamd 
                 * "backdoor.php.png" uploaden om webservers te exploiteren. We hernoemen het bestand naar een 
                 * onraadbare cryptografische string (`bin2hex(random_bytes(16))`).
                 */
                $stored = bin2hex(random_bytes(16)) . "." . $ext;
                move_uploaded_file($file["tmp_name"], "uploads/" . $stored);

                // Genereer een unieke, veilige download-token (64 tekens lang)
                $token = bin2hex(random_bytes(32));
                // Hash het download-wachtwoord veilig met bcrypt
                $hashedPassword = password_hash($_POST["password"], PASSWORD_DEFAULT);

                // Sla alle metadata en de relatie met de user_id veilig op in de database via een Prepared Statement
                $stmt = $conn->prepare("INSERT INTO uploads (user_id, share_token, original_name, stored_name, mime_type, file_hash, password) VALUES (?,?,?,?,?,?,?)");
                $stmt->execute([$_SESSION['user_id'], $token, basename($file["name"]), $stored, $file["type"], $hash, $hashedPassword]);

                // Redirect naar de pagina met de schone linkparameter
                header("Location: ?link=" . $token);
                exit;
            }
        }
    }
}

// Haal alle uploads op die toebehoren aan de huidige ingelogde gebruiker om te tonen in de tabel
$stmt = $conn->prepare("SELECT original_name, share_token, uploaded_at FROM uploads WHERE user_id = ? ORDER BY uploaded_at DESC");
$stmt->execute([$_SESSION['user_id']]);
$myUploads = $stmt->fetchAll(PDO::FETCH_ASSOC);
?>
<!DOCTYPE html>
<html lang="nl">
<head>
<meta charset="UTF-8">
<title>Upload & Dashboard</title>
<style>
table { border-collapse: collapse; width: 100%; margin-top: 20px; }
th, td { border: 1px solid #ccc; padding: 10px; text-align: left; }
th { background-color: #f4f4f4; }
</style>
</head>
<body>
<div style="text-align: right;">
<a href="logout.php">Uitloggen</a>
</div>

<h1>Upload Nieuw Bestand</h1>
<form method="post" enctype="multipart/form-data">
<input type="file" name="fileToUpload" accept="image/*">
<input type="password" name="password" placeholder="Wachtwoord voor download" required>
<input type="submit" value="Uploaden" name="submit">
</form>

<?php if($error): ?><p style="color:red"><?= htmlspecialchars($error) ?></p><?php endif; ?>

<?php if($shareLink): ?>
<p style="color:green; font-weight:bold;">Succes! Jouw link: <a href="<?= $shareLink ?>"><?= $shareLink ?></a></p>
<script>history.replaceState(null, "", window.location.pathname);</script>
<?php endif; ?>

<hr>

<h2>Mijn Geüploade Bestanden</h2>
<?php if(count($myUploads) > 0): ?>
<table>
<tr>
<th>Bestandsnaam</th>
<th>Deellink</th>
<th>Datum geüpload</th>
</tr>
<?php foreach($myUploads as $upload): ?>
<tr>
<td><?= htmlspecialchars($upload['original_name']) ?></td>
<td><a href="download.php?token=<?= htmlspecialchars($upload['share_token']) ?>" target="_blank">Open Link</a></td>
<td><?= htmlspecialchars($upload['uploaded_at']) ?></td>
</tr>
<?php endforeach; ?>
</table>
<?php else: ?>
<p>Je hebt nog geen bestanden geüpload.</p>
<?php endif; ?>

</body>
</html>