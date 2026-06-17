<?php
$conn = new PDO("mysql:host=localhost;dbname=cybersecurity", "root", "");
$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

$token = $_GET["token"] ?? "";
$stmt = $conn->prepare("SELECT * FROM uploads WHERE share_token = ?");
$stmt->execute([$token]);
$file = $stmt->fetch(PDO::FETCH_ASSOC);

if(!$file) die("Niet gevonden.");

$error = "";
$toegang = false;

if(isset($_POST["password"])) {
if(password_verify($_POST["password"], $file["password"] ?? "")) {
        $toegang = true;
    } else {
        $error = "Verkeerd wachtwoord.";
    }
}

if($toegang && isset($_GET["download"])) {
    $path = "uploads/" . $file["stored_name"];
    header("Content-Type: " . $file["mime_type"]);
    header("Content-Disposition: attachment; filename=\"" . $file["original_name"] . "\"");
    header("Content-Length: " . filesize($path));
    readfile($path);
    exit;
}
?>
<!DOCTYPE html>
<html lang="nl">
<head><meta charset="UTF-8"><title><?= htmlspecialchars($file["original_name"]) ?></title></head>
<body>
    <?php if(!$toegang): ?>
        <h1>Wachtwoord vereist</h1>
        <form method="post">
            <input type="password" name="password" placeholder="Wachtwoord">
            <input type="submit" value="Toegang">
        </form>
        <?php if($error): ?><p style="color:red"><?= $error ?></p><?php endif; ?>
    <?php else: ?>
        <h1><?= htmlspecialchars($file["original_name"]) ?></h1>
        <img src="uploads/<?= htmlspecialchars($file["stored_name"]) ?>" style="max-width:100%"><br><br>
        <a href="?token=<?= htmlspecialchars($token) ?>&download=1">Download</a>
    <?php endif; ?>
</body>
</html>