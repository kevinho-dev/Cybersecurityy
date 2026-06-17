<?php
session_start();
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit;
}

$conn = new PDO("mysql:host=localhost;dbname=cybersecurity", "root", "");
$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

$shareLink = $error = "";

if(isset($_GET["link"])) {
    $shareLink = "http://localhost/cybersecurity/download.php?token=" . $_GET["link"];
}

if(isset($_POST["submit"])) {
    $file = $_FILES["fileToUpload"];
    $ext = strtolower(pathinfo($file["name"], PATHINFO_EXTENSION));

    if(!getimagesize($file["tmp_name"]))                       $error = "Geen afbeelding.";
    elseif(!in_array($ext, ["jpg","jpeg","png","gif","webp"])) $error = "Verkeerd bestandstype.";
    elseif($file["size"] > 5000000)                            $error = "Te groot (max 5MB).";
    elseif(empty($_POST["password"]))                          $error = "Vul een wachtwoord in.";
    else {
        $hash = hash_file("sha256", $file["tmp_name"]);

        $stmt = $conn->prepare("SELECT share_token FROM uploads WHERE file_hash = ?");
        $stmt->execute([$hash]);
        $existing = $stmt->fetch(PDO::FETCH_ASSOC);

        if($existing) {
            header("Location: ?link=" . $existing["share_token"]);
            exit;
        } else {
            $stored = bin2hex(random_bytes(16)) . "." . $ext;
            move_uploaded_file($file["tmp_name"], "uploads/" . $stored);

            $token = bin2hex(random_bytes(32));
            $hashedPassword = password_hash($_POST["password"], PASSWORD_DEFAULT);
            
            $stmt = $conn->prepare("INSERT INTO uploads (share_token, original_name, stored_name, mime_type, file_hash, password) VALUES (?,?,?,?,?,?)");
            $stmt->execute([$token, basename($file["name"]), $stored, $file["type"], $hash, $hashedPassword]);

            header("Location: ?link=" . $token);
            exit;
        }
    }
}
?>
<!DOCTYPE html>
<html lang="nl">
<head><meta charset="UTF-8"><title>Upload</title></head>
<body>
    <div style="text-align: right;">
        <a href="logout.php">Uitloggen</a>
    </div>

    <h1>Upload</h1>
    <form method="post" enctype="multipart/form-data">
        <input type="file" name="fileToUpload" accept="image/*">
        <input type="password" name="password" placeholder="Wachtwoord voor download" required>
        <input type="submit" value="Uploaden" name="submit">
    </form>
    <?php if($error): ?><p style="color:red"><?= htmlspecialchars($error) ?></p><?php endif; ?>
    <?php if($shareLink): ?>
        <p>Link: <a href="<?= $shareLink ?>"><?= $shareLink ?></a></p>
        <script>history.replaceState(null, "", window.location.pathname);</script>
    <?php endif; ?>
</body>
</html>