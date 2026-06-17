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

        // Now we also check if THIS specific user already uploaded this exact file
        $stmt = $conn->prepare("SELECT share_token FROM uploads WHERE file_hash = ? AND user_id = ?");
        $stmt->execute([$hash, $_SESSION['user_id']]);
        $existing = $stmt->fetch(PDO::FETCH_ASSOC);

        if($existing) {
            header("Location: ?link=" . $existing["share_token"]);
            exit;
        } else {
            $stored = bin2hex(random_bytes(16)) . "." . $ext;
            move_uploaded_file($file["tmp_name"], "uploads/" . $stored);

            $token = bin2hex(random_bytes(32));
            $hashedPassword = password_hash($_POST["password"], PASSWORD_DEFAULT);
            
            // Added user_id to the INSERT query
            $stmt = $conn->prepare("INSERT INTO uploads (user_id, share_token, original_name, stored_name, mime_type, file_hash, password) VALUES (?,?,?,?,?,?,?)");
            $stmt->execute([$_SESSION['user_id'], $token, basename($file["name"]), $stored, $file["type"], $hash, $hashedPassword]);

            header("Location: ?link=" . $token);
            exit;
        }
    }
}

// Fetch all uploads for the currently logged-in user
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