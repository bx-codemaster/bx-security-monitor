# Changelog

Alle nennenswerten Änderungen am Modul bx-security-monitor werden in dieser Datei dokumentiert.

Format orientiert sich an Keep a Changelog.

## [1.1.0] - 2026-07-11

### Added
- ReDoS-Härtung in der Scanner-Engine durch Begrenzung von Pfad und URI vor Regex-Auswertung.
- Optionales, DB-unabhängiges Rate-Limiting über APCu zur Ergänzung der Score-basierten Erkennung.
- Intervallbasiertes Housekeeping via APCu-Zeitstempel mit probabilistischem Fallback.
- Erweiterte Erkennungsregeln und strukturierte Kategorisierung verdächtiger Requests.
- Dokumentation der Weiterentwicklung im Modulordner unter docs/README.MD.

### Changed
- Race-Condition-Schutz im Bewertungsfenster durch MySQL GET_LOCK pro IP (Insert/Score/Block-Entscheidung serialisiert).
- Login-Guard erweitert, sodass neben login.php auch der Reparaturpfad login_admin.php überwacht werden kann.
- Fehlversuchs-Erkennung im Reparaturpfad von textbasierter Ausgabeprüfung auf explizites internes Flag umgestellt.
- Beschreibung zu msec_admin_sessions in der Projektdokumentation präzisiert: Session-Schreiblogik via bx_security_session.php ist vorhanden; zusätzlicher Admin-Hook ist optional.

### Fixed
- Robustere Erfassung fehlgeschlagener Reparatur-Logins in Kombination aus login_admin.php und includes/login_admin.php.
- Missverständliche Dokumentationsaussage zum Admin-Session-Tracking korrigiert.

### Security
- Bessere Stabilität unter paralleler Last durch Locking im Block-Entscheidungsfenster.
- Zusätzliche Schutzschicht für high-volume Requests ohne klassisches Angriffsmuster durch APCu-Rate-Limit.

### Notes
- Die Tabelle msec_admin_sessions wird im aktuellen Stand über includes/extra/application_top/application_top_end/bx_security_session.php befüllt.
- Ein separater Admin-Hook analog 90_msec_admin_session.php aus dem Ursprungspaket kann bei speziellen Betriebswegen ergänzend eingesetzt werden.

## [1.0.0] - Ursprungsversion

### Added
- Grundlegender Security Monitor für modified eCommerce.
- Pattern-basierte Scanner- und Angriffserkennung mit Punktesystem.
- Temporäre IP-Blockierung bei Schwellwertüberschreitung.
- Passiver Admin-Login-Wächter ohne Kontosperre.
- Admin-Oberfläche mit Ereignis-, Block- und Whitelist-Verwaltung.
- Manuelle Regeln (exact, prefix, contains) mit konfigurierbarer Punktzahl.

### Notes
- Ursprungstexte:
  - security-monitor-for-modified-1.0.0/README_DE.txt
  - security-monitor-for-modified-1.0.0/BESCHREIBUNG_FUER_WEITERGABE.txt

[1.1.0]: ../docs/CHANGELOG.MD
[1.0.0]: ../security-monitor-for-modified-1.0.0/README_DE.txt
