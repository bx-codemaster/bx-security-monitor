# Zwei Schutzschichten: xss_secure.php und bx_guard.php

Kurzfassung für alle, die es eilig haben: Wir haben zwei unabhängige Security-Systeme im Shop laufen, die sich ergänzen statt zu überschneiden. `xss_secure.php` ist alt und prüft **Eingabewerte**, `bx_guard.php` (Teil unseres Security-Monitor-Moduls) ist neu und prüft **URL-Pfade**. Seit Kurzem teilen sich beide dieselbe Whitelist.

---

## 1. Warum es überhaupt zwei Systeme gibt

`xss_secure.php` stammt aus der ursprünglichen modified-Shop-Codebasis und ist seit Jahren Teil des Cores. `bx_guard.php` ist unser eigenes, neueres Modul (`bx_security_monitor`), das über den offiziellen Erweiterungsmechanismus (`includes/extra/application_top/application_top_begin/`) eingehängt wird.

Wir haben `xss_secure.php` **nicht** abgelöst, weil beide Systeme strukturell unterschiedliche Dinge prüfen und sich damit gegenseitig ergänzen, statt sich zu duplizieren. Mehr dazu in Abschnitt 3.

---

## 2. Der zeitliche Ablauf eines Requests

Beide Systeme laufen innerhalb von `application_top.php`, aber zu sehr unterschiedlichen Zeitpunkten:

1. **Request kommt rein** – `$_GET`/`$_POST`/`$_COOKIE` sind noch roh, ungefiltert.
2. **`xss_secure.php`** wird als *allererste Zeile* von `application_top.php` eingebunden. Zu diesem Zeitpunkt existiert **noch keine Datenbankverbindung** und **noch keine geladene Konfiguration**.
3. **`InputFilter`** bereinigt anschließend `$_GET`, `$_POST` und `$_REQUEST` (HTML-Encoding, SQL-Escaping).
4. **Datenbankverbindung + Konfiguration** werden aufgebaut (`xtc_db_connect()`, Config aus der `configuration`-Tabelle).
5. **`bx_guard.php`** läuft über den Hook-Ordner `application_top_begin` – zu diesem Zeitpunkt stehen DB, Konfiguration und unsere eigenen Tabellen (`msec_whitelist`, `msec_blocks` etc.) zur Verfügung.
6. **Rest der Anwendung** läuft normal weiter.

**Der wichtige Punkt:** `xss_secure.php` kann aus technischen Gründen keine Datenbankabfragen machen – deshalb ist es bewusst als eigenständiges, DB-unabhängiges System gebaut. Das ist kein Design-Fehler, sondern eine Notwendigkeit angesichts des frühen Einbindungszeitpunkts.

---

## 3. Was jedes System tatsächlich prüft

### xss_secure.php – wertbasierte Prüfung

Prüft den **Inhalt** von `$_GET`, `$_POST` und `$_COOKIE` gegen eine Reihe von Regex-Mustern:

- HTML-Tags mit Angriffspotenzial: `<script>`, `<iframe>`, `<object>`, `<applet>`, `<meta>`, `<style>`, `<form>`, `<img>` u. a.
- JavaScript-Anker: `window`, `alert`, `document`, `cookie`
- SQL-Fragmente: `select`, `concat`, sowie Muster wie `... or ... =` / `... and ... like`

Bei Treffer:
- IP wird für **1 Stunde** in `log/xss_blacklist.log` gesperrt (Flatfile, kein DB-Eintrag)
- Optional wird ein ausführlicher Vorfallbericht geloggt (`log/xss_attacks_*.log.gz`)
- Weiterleitung auf `error.html`

**Wichtig für die Fehlersuche:** Diese Regeln sind **breit** gefasst – z. B. matcht `select`/`concat` jeden Teilstring, nicht nur echte SQL-Syntax. Ein Firmenname wie "Selective Consulting" oder ein Feld mit "concatenated_id" kann bereits auslösen. Das ist der häufigste Grund für unerwartete Sperren bei legitimen Kunden.

### bx_guard.php – pfadbasierte Prüfung

Prüft **nicht** die Eingabewerte, sondern `REQUEST_URI`/Pfad der Anfrage gegen ein Regelwerk mit Score-System. Abgedeckte Kategorien:

1. WordPress-Scanner (`/wp-`, `/wordpress/`, `xmlrpc.php`, `wlwmanifest.xml`)
2. Sensible Pfade (`.env`, `.git`, `.svn`, `.hg`, `.bzr`, `.vscode`, `.idea`)
3. phpMyAdmin-/Adminer-Scanner (`/pma/`, `/myadmin/`, `/dbadmin/` u. a.)
4. PHPUnit-/bekannte Exploitpfade
5. Typische Webshell-Dateinamen (feste Liste bekannter Namen)
6. Backup-/Datenbank-/Dump-Dateien (`.sql`, `.bak`, `.old` u. a.)
7. FTP- und Mirror-Scanner (`.ftpconfig`, `ws_ftp.ini`, `.netrc`, `sitemanager.xml`, Mirror-Pfade)
8. Verzeichniswechsel (`../`)
9. Local-File-Inclusion-Muster (`/etc/passwd`, `php://filter`)
10. Eindeutige SQL-Injection-Muster (bewusst eng gefasst, um False Positives zu minimieren)
11. Eindeutige XSS-Muster (bewusst eng gefasst)
12. Eindeutige Command-Injection-Muster (erfordert Separator wie `;`, `|`, `&&`)
13. Ungewöhnliche HTTP-Methoden (`TRACE`, `TRACK`, `CONNECT`)

Jeder Treffer erhöht einen **Score**. Wird ein konfigurierbarer Schwellenwert überschritten, landet die IP in `msec_blocks` (DB-Tabelle) mit Grund, Kategorie, Score und Sperrzeit (`MODULE_BX_SECURITY_BLOCK_HOURS`).

**Wichtig für die Fehlersuche:** Diese Regeln sind bewusst **enger** gefasst als bei `xss_secure.php`, gerade um False Positives bei echten Kunden-URLs zu vermeiden. Ein Treffer hier deutet fast immer auf einen echten automatisierten Scan hin, nicht auf einen zufälligen Kundennamen.

---

## 4. Vergleichstabelle

| | xss_secure.php | bx_guard.php |
|---|---|---|
| Prüft | Inhalt von `$_GET`/`$_POST`/`$_COOKIE` | `REQUEST_URI` / Pfad |
| Läuft | Vor DB-Verbindung, vor `InputFilter` | Nach DB-Verbindung, nach `InputFilter` |
| Typischer Treffer | Formularfeld mit `<script>` oder SQL-Fragment | Scanner ruft `/wp-admin/`, `/.git/config` etc. auf |
| Speicherort Sperre | Flatfile `log/xss_blacklist.log` | DB-Tabelle `msec_blocks` |
| Sperrdauer | Fix, 1 Stunde | Konfigurierbar (`MODULE_BX_SECURITY_BLOCK_HOURS`) |
| Whitelist | Über Mirror-Datei (siehe Abschnitt 5) | Nativ, `msec_whitelist`-Tabelle |
| Regelstrenge | Breiter, mehr False-Positive-Risiko | Enger, auf eindeutige Muster fokussiert |
| Admin-Sichtbarkeit | Eigene Seite `blacklist_logs.php` | Security-Monitor-Panel (Dashboard, Score, Kategorien) |

---

## 5. Die gemeinsame Whitelist

Ursprünglich kannte `xss_secure.php` unsere `msec_whitelist`-Tabelle nicht. Das führte zu einem konkreten Risiko: Eine im Security-Monitor whitelistete IP (z. B. ein Admin, der versehentlich geblockt wurde) konnte trotzdem von `xss_secure.php` gesperrt werden – ohne jede Override-Möglichkeit außer manuellem Löschen der Flatfile.

**Warum wir keine direkte Funktion teilen konnten:** `msec_is_trusted_ip()` braucht eine Datenbankverbindung. `xss_secure.php` läuft aber, bevor diese existiert (siehe Abschnitt 2). Ein direkter Funktionsaufruf war also nicht möglich.

**Die Lösung – ein dateibasierter Spiegel:**

- Jede Änderung an der Whitelist im Admin-Panel (Hinzufügen/Entfernen einer IP) schreibt automatisch eine reine Textdatei: `log/msec_whitelist_mirror.log` (eine IP pro Zeile).
- Das Schreiben erfolgt atomar (`.tmp`-Datei + `rename()`), damit nie eine unvollständige Datei gelesen wird.
- `xss_secure.php` liest diese Datei vor jeder Blacklist-Prüfung – reines Datei-Lesen, keine DB nötig, funktioniert also auch zu diesem frühen Zeitpunkt.

**Praktische Folge:** Eine IP, die im Security-Monitor-Panel whitelistet wird, ist jetzt automatisch auch für `xss_secure.php` von der Sperre ausgenommen – ohne dass beide Systeme sich sonst irgendwie kennen müssen.

---

## 6. Core-Patches: login_admin.php und xss_secure.php selbst

Zusätzlich zur Whitelist-Synchronisation patchen wir zwei Core-Dateien direkt, um zusätzliche Erfassung zu ermöglichen:

- **`login_admin.php`**: Bei fehlgeschlagenen Admin-Login-Versuchen wird zusätzlich unser `bx_admin_login_guard.php` geladen, um diese Versuche im Security-Monitor sichtbar zu machen.
- **`xss_secure.php`** selbst wird ebenfalls gepatcht (Details siehe Admin-Panel-Statusanzeige).

Beide Patches werden bei der Modul-Installation automatisch eingespielt, mit Backup der Originaldatei und Hash-Verifikation, um stille Core-Updates zu erkennen. Der aktuelle Patch-Status ist im Security-Monitor-Panel sichtbar (grün = aktiv und unverändert, gelb/orange = Core wurde seither verändert oder Patch ist inaktiv).

**Für die Fehlersuche wichtig:** Falls nach einem Shop-Core-Update Login-Versuche plötzlich nicht mehr im Security-Monitor auftauchen, zuerst den Patch-Status im Panel prüfen – ein Core-Update kann die gepatchten Dateien überschrieben haben.

---

## 7. Troubleshooting: Wo schaue ich nach?

| Symptom | Wahrscheinliche Ursache | Wo nachschauen |
|---|---|---|
| Kunde meldet "Seite blockiert" nach Formular-Absenden | `xss_secure.php`, oft False Positive bei breiten Regex-Mustern | `log/xss_blacklist.log`, Admin-Seite `blacklist_logs.php` |
| Kunde/Bot wird beim Aufruf einer bestimmten URL geblockt | `bx_guard.php` | Security-Monitor-Panel → Events/Blocks, dort Grund & Kategorie |
| Admin kann sich nicht einloggen, obwohl Zugangsdaten korrekt | Möglicher Fehlalarm im Login-Guard oder aktive Sperre | Security-Monitor-Panel → Blocks, IP dort suchen |
| Whitelistete IP wird trotzdem gesperrt | Mirror-Datei nicht aktuell (z. B. nach manuellem DB-Eingriff) | Whitelist im Panel neu speichern (triggert Re-Sync), danach `log/msec_whitelist_mirror.log` auf Aktualität prüfen |
| Core-Patch-Status zeigt "mismatch" oder "target_missing" | Shop-Core-Update hat gepatchte Datei überschrieben | Patch im Security-Monitor-Panel neu einspielen |

---

## 8. Kurz zusammengefasst

- **Zwei Systeme, zwei Blickwinkel**: `xss_secure.php` schaut auf *Werte*, `bx_guard.php` schaut auf *Pfade*. Beide zusammen decken mehr ab als jedes für sich.
- **Der frühe Ausführungszeitpunkt von `xss_secure.php` ist kein Bug**, sondern zwingend, weil zu diesem Zeitpunkt keine Datenbankverbindung existiert.
- **Die Whitelist wird über eine Spiegeldatei geteilt**, weil ein direkter Funktionsaufruf mangels DB-Verbindung nicht möglich ist.
- **Beide Systeme sind im Security-Monitor-Panel sichtbar** – Blocks aus `bx_guard.php` direkt, Blocks aus `xss_secure.php` über die separate `blacklist_logs.php`-Seite.
