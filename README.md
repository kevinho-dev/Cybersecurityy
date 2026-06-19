# kevinstopmettelaatkomen — File sharing site

Leander, Kevin, Faisal, Bram | Projectweek 2026

---

## Inhoudsopgave

- [Wat doet de site?](#wat-doet-de-site)
- [Bestandsstructuur](#bestandsstructuur)
- [Hoe werkt de code?](#hoe-werkt-de-code)
  - [config.php](#configphp)
  - [index.php (dashboard)](#indexphp--dashboard)
  - [login.php & register.php](#loginphp--registerphp)
  - [logout.php](#logoutphp)
  - [download.php](#downloadphp)
  - [verify.php](#verifyphp)
  - [thumbnail.php](#thumbnailphp)
  - [logger.php & logs.php](#loggerphp--logsphp)
  - [dashboard.js](#dashboardjs)
  - [download.js](#downloadjs)
- [Database structuur](#database-structuur)
- [Beveiliging](#beveiliging)
- [Link naar GitHub](#link-naar-github)

---

## Wat doet de site?

De site is een beveiligd file-sharing platform. Een gebruiker maakt een account aan, logt in, en upload daarna een bestand. Bij het uploaden kies je een download-wachtwoord. De site genereert daarna een deelbare link. Iedereen die die link opent, moet eerst inloggen op een account en daarna het wachtwoord van het bestand invoeren voor ze het bestand kunnen downloaden. Zo zijn bestanden altijd dubbel beveiligd: achter een account én achter een wachtwoord.

---

## Bestandsstructuur

```
/
├── index.php            — Dashboard: uploaden en overzicht van eigen bestanden
├── htaccess             — Blokkeert directe toegang tot de /uploads/ map
├── php/
│   ├── config.php       — Sessie-instellingen en databaseverbinding (PDO)
│   ├── login.php        — Inloggen
│   ├── register.php     — Nieuw account aanmaken
│   ├── logout.php       — Sessie vernietigen
│   ├── download.php     — Publieke downloadpagina (vereist account + wachtwoord)
│   ├── verify.php       — AJAX-endpoint: controleert het bestandswachtwoord
│   ├── thumbnail.php    — Stuurt een verkleinde preview van een afbeelding
│   ├── logger.php       — Centrale logging-functie
│   └── logs.php         — Activiteitenlog (gebruiker ziet eigen logs, admin ziet alles)
├── js/
│   ├── dashboard.js     — Wachtwoord-modal logica op het dashboard
│   └── download.js      — Wachtwoord-modal logica op de downloadpagina
├── css/
│   └── style.css        — Dark glass-morphism styling
└── uploads/             — Opgeslagen bestanden (geblokkeerd via htaccess)
```

---

## Hoe werkt de code?

### config.php

`config.php` wordt als eerste geladen op elke pagina via `require_once`. Het regelt drie dingen:

1. **Sessie-beveiliging** — De sessie-cookie krijgt de `httponly` en `SameSite=Lax` flags mee. Op HTTPS wordt ook `Secure` ingesteld zodat de cookie nooit over HTTP verstuurd wordt.
2. **User-Agent check** — Als de User-Agent halverwege een sessie verandert, wordt de sessie direct vernietigd. Dit beschermt tegen gestolen sessie-cookies.
3. **Databaseverbinding** — Er wordt een PDO-verbinding geopend met de MySQL-database. PDO gebruikt prepared statements, waardoor SQL-injecties niet mogelijk zijn. Als de verbinding mislukt, krijgt de gebruiker een vage foutmelding (de echte fout wordt niet getoond, want die kan database-namen en wachtwoorden lekken).

---

### index.php — Dashboard

Dit is de hoofdpagina. Je komt hier alleen als je ingelogd bent, anders word je doorgestuurd naar `login.php`.

**Uploaden**

- De gebruiker selecteert een bestand en kiest een download-wachtwoord.
- De server controleert het bestandstype op twee manieren: de extensie én het echte MIME-type via `finfo_file`. Alleen afbeeldingen, PDF, Word, Excel en TXT zijn toegestaan.
- Bestanden boven de 25 MB worden geweigerd.
- De bestandsinhoud wordt gehasht met SHA-256. Als dezelfde gebruiker hetzelfde bestand al eerder heeft geüpload, wordt de bestaande link teruggegeven in plaats van een duplicaat op te slaan.
- De bestandsnaam op de server is een willekeurige reeks tekens (`bin2hex(random_bytes(16))`), zodat de originele naam niet te raden is via de URL.
- Het download-wachtwoord wordt gehasht opgeslagen met `password_hash()` (bcrypt).
- Na de upload wordt een willekeurig 64-tekens lange share-token gegenereerd en opgeslagen in de database.

**Overzicht**

Onderaan het dashboard ziet de ingelogde gebruiker een tabel met al zijn geüploade bestanden. Voor afbeeldingen wordt een miniatuur getoond via `thumbnail.php`. De knoppen "Share link" en "Download" openen een wachtwoord-modal.

---

### login.php & register.php

**login.php**

De gebruiker vult een gebruikersnaam en wachtwoord in. De server zoekt de gebruiker op via een prepared statement en vergelijkt het wachtwoord met `password_verify()`. Als de login slaagt wordt de sessie-ID direct ververst met `session_regenerate_id(true)` om session fixation te voorkomen.

Als de bezoeker via een download-link naar de loginpagina gestuurd werd (omdat ze nog niet ingelogd waren), staat de originele URL opgeslagen in een `?next=` parameter. Na een succesvolle login worden ze automatisch teruggestuurd naar die downloadpagina. Alleen `download.php`-URLs worden geaccepteerd als return-URL om open redirects te voorkomen.

De foutmelding bij een verkeerde login is bewust vaag ("Invalid username or password") zodat aanvallers niet kunnen zien of een gebruikersnaam wél bestaat maar het wachtwoord verkeerd is.

**register.php**

Nieuwe gebruikers kiezen een gebruikersnaam en wachtwoord (minimaal 8 tekens). Het wachtwoord moet twee keer ingevuld worden. Als de gebruikersnaam al bestaat, krijgt de gebruiker een foutmelding. Het wachtwoord wordt opgeslagen als bcrypt-hash.

---

### logout.php

Uitloggen bestaat uit drie stappen:

1. Alle sessie-variabelen uit het geheugen verwijderen (`$_SESSION = []`)
2. De sessie-cookie in de browser verwijderen door de vervaldatum in het verleden te zetten
3. De sessiedata op de server vernietigen met `session_destroy()`

Na uitloggen wordt de gebruiker doorgestuurd naar de loginpagina.

---

### download.php

Dit is de pagina die de deelbare link opent. Er zijn nu twee lagen beveiliging:

1. **Account-gate** — Als de bezoeker niet ingelogd is, wordt hij doorgestuurd naar `login.php`. De originele download-URL wordt meegegeven als `?next=` parameter zodat de bezoeker na het inloggen automatisch terugkomt op de juiste downloadpagina.
2. **Wachtwoord-gate** — Na het inloggen moet de bezoeker alsnog het download-wachtwoord van het bestand invoeren. Pas daarna wordt het bestand geserveerd.

Het bestand wordt niet direct via een publieke URL geserveerd. In plaats daarvan leest de server het bestand van schijf via `readfile()` en stuurt het met de juiste `Content-Type` en `Content-Disposition` headers. De echte bestandsnaam op de server is nooit zichtbaar voor de gebruiker.

---

### verify.php

`verify.php` is een AJAX-endpoint dat wordt aangeroepen via `fetch()` vanuit JavaScript. Het ontvangt een `token` en een `password`, zoekt het bijbehorende bestand op in de database, en controleert het wachtwoord met `password_verify()`.

Als het wachtwoord klopt, wordt `$_SESSION['unlocked_tokens'][$token] = true` ingesteld. `download.php` kijkt naar deze sessiesleutel om te weten of de gebruiker het wachtwoord al heeft ingevuld. Zo hoeft de gebruiker het wachtwoord maar één keer per sessie in te voeren.

Het endpoint geeft altijd JSON terug: `{"success": true}` of `{"success": false, "error": "..."}`.

---

### thumbnail.php

Dit bestand genereert een verkleinde versie van een geüploade afbeelding voor het dashboard. Het ontvangt een share-token, zoekt de bijbehorende bestandsnaam op in de database, en stuurt de afbeelding als response. Zo worden de echte bestandsnamen op de server nooit blootgesteld.

---

### logger.php & logs.php

**logger.php** bevat één functie: `logEvent()`. Die wordt aangeroepen op elk belangrijk moment in de applicatie: bij uploads, downloads, succesvolle logins, mislukte logins en fout ingevoerde bestandswachtwoorden. Elke log-regel bevat het type event, de gebruikersnaam, het bestandsnaam en het IP-adres.

**logs.php** toont de activiteitenlog aan de ingelogde gebruiker. Gewone gebruikers zien alleen hun eigen activiteit. Gebruikers met de rol `admin` zien alle activiteit van alle gebruikers in het systeem, inclusief een extra kolom met de gebruikersnaam.

---

### dashboard.js

`dashboard.js` regelt de wachtwoord-modal op het dashboard. Als een gebruiker op "Share link" of "Download" klikt, wordt de modal geopend. De modal wordt gevuld met de bestandsnaam en het share-token uit de `data-` attributen van de knop.

Bij het versturen van het formulier wordt `verify.php` aangeroepen via `fetch()`. Bij een correct wachtwoord:

- Bij "Download": de browser wordt doorgestuurd naar `download.php` met `?direct=1`
- Bij "Share link": de download-URL wordt naar het klembord gekopieerd

De modal kan gesloten worden via de ×-knop, door op de achtergrond te klikken, of met de Escape-toets.

Daarnaast regelt `dashboard.js` ook de bestandspreview in het uploadformulier. Zodra een bestand geselecteerd is, toont het formulier de bestandsnaam, de bestandsgrootte en (voor afbeeldingen) een miniatuurpreview. Er is een ×-knop om de selectie ongedaan te maken.

---

### download.js

`download.js` werkt hetzelfde als de modal-logica in `dashboard.js`, maar dan voor de downloadpagina. De modal wordt direct zichtbaar getoond als het bestand een wachtwoord heeft. Na een correct wachtwoord wordt de browser doorgestuurd naar dezelfde pagina met `?download=1` toegevoegd, waarna `download.php` het bestand serveert.

---

## Database structuur

De applicatie gebruikt twee tabellen:

**users**

| Kolom      | Type         | Beschrijving                          |
|------------|--------------|---------------------------------------|
| id         | INT (PK)     | Automatisch oplopend ID               |
| username   | VARCHAR(255) | Unieke gebruikersnaam                 |
| password   | VARCHAR(255) | bcrypt-hash van het wachtwoord        |
| role       | VARCHAR(20)  | `user` of `admin`                     |

**uploads**

| Kolom         | Type         | Beschrijving                                      |
|---------------|--------------|---------------------------------------------------|
| id            | INT (PK)     | Automatisch oplopend ID                           |
| user_id       | INT (FK)     | Verwijzing naar de eigenaar in `users`            |
| share_token   | VARCHAR(255) | Willekeurige 64-tekens lange deelbare token       |
| original_name | VARCHAR(255) | Originele bestandsnaam (voor weergave)            |
| stored_name   | VARCHAR(255) | Willekeurige bestandsnaam op de server            |
| mime_type     | VARCHAR(100) | Echt MIME-type van het bestand                    |
| file_hash     | VARCHAR(255) | SHA-256 hash van de bestandsinhoud                |
| password      | VARCHAR(255) | bcrypt-hash van het download-wachtwoord           |
| uploaded_at   | DATETIME     | Tijdstip van uploaden                             |

**logs**

| Kolom       | Type         | Beschrijving                                     |
|-------------|--------------|--------------------------------------------------|
| id          | INT (PK)     | Automatisch oplopend ID                          |
| event_type  | VARCHAR(30)  | upload / download / login_success / login_failed / unlock_failed |
| username    | VARCHAR(255) | Gebruikersnaam op het moment van het event       |
| user_id     | INT          | ID van de gebruiker (NULL bij mislukte login)    |
| file_name   | VARCHAR(255) | Naam van het betrokken bestand                   |
| ip_address  | VARCHAR(45)  | IP-adres van de bezoeker                         |
| details     | VARCHAR(255) | Extra informatie (bijv. foutmelding)             |
| created_at  | DATETIME     | Tijdstip van het event                           |

---

## Beveiliging

| Risico | Maatregel |
|---|---|
| SQL-injectie | PDO prepared statements op alle database-queries |
| Wachtwoorden in plaintext | bcrypt via `password_hash()` / `password_verify()` |
| Gevaarlijke bestandstypes | Whitelist op extensie én MIME-type via `finfo_file` |
| Te grote bestanden | Limiet van 25 MB |
| Directe toegang tot uploads | `.htaccess` blokkeert de `/uploads/` map; bestanden worden via PHP geserveerd |
| Session fixation | `session_regenerate_id(true)` na elke succesvolle login |
| Gestolen cookies (XSS) | `httponly` sessie-cookie |
| Cross-site request forgery | `SameSite=Lax` sessie-cookie |
| Open redirect na login | `?next=` parameter accepteert alleen `download.php`-URLs |
| Bestandsnaam raden | Opgeslagen bestandsnamen zijn willekeurige hex-strings |
| Foutmeldingen die info lekken | Generieke foutmeldingen bij login en database-errors |
| Dubbele uploads | SHA-256 hash-check per gebruiker voorkomt duplicaten |

---

## Link naar GitHub

https://github.com/kevinho-dev/Cybersecurityy
