# Weiterentwicklung Security Monitor

## Zweck dieses Dokuments
Dieses Dokument beschreibt die Weiterentwicklung vom Ursprungspaket
security-monitor-for-modified-1.0.0
zum aktuellen Modulstand unter
bx-codemaster/bx-security-monitor.

Es dient als technische und fachliche Übergabedokumentation für Entwicklung, Betrieb und spätere Releases.

## Verwendete Quellen
- security-monitor-for-modified-1.0.0/README_DE.txt
- security-monitor-for-modified-1.0.0/BESCHREIBUNG_FUER_WEITERGABE.txt
- bx-codemaster/bx-security-monitor/src/includes/modules/bx_guard.php
- bx-codemaster/bx-security-monitor/src/includes/modules/bx_admin_login_guard.php
- bx-codemaster/bx-security-monitor/src/includes/extra/application_top/application_top_begin/bx_security_bootstrap.php
- bx-codemaster/bx-security-monitor/src/includes/extra/application_top/application_top_end/bx_security_session.php
- bx-codemaster/bx-security-monitor/src/admin/includes/modules/system/bx_security_monitor.php
- bx-codemaster/bx-security-monitor/src/admin/bx_security_monitor.php

## Kurzüberblick: Was bleibt gleich
Aus den Ursprungstexten README_DE.txt und BESCHREIBUNG_FUER_WEITERGABE.txt wurden die zentralen Produktaussagen übernommen:
- Scanner- und Angriffserkennung über Muster und Punktesystem
- Temporäre automatische IP-Blockierung
- Passiver Admin-Login-Schutz ohne Kontosperre und ohne 2FA-Zwang
- Dashboard mit Ereignissen, Blöcken, Kategorien und Top-Zielen
- Whitelist und manuelle Regeln
- Keine externe API, keine Cloud-Abhängigkeit, Speicherung in der lokalen Datenbank

## Kurzüberblick: Was wurde erweitert
Im aktuellen Modulstand 1.2.8 wurden gegenüber 1.0.0 insbesondere folgende technische Verbesserungen umgesetzt:
- ReDoS-Härtung durch Längenbegrenzung von Pfad und URI vor Regex-Auswertung
- Race-Condition-Schutz im Scoring/Blocking durch GET_LOCK je IP
- Housekeeping nicht mehr nur zufällig, sondern intervallbasiert mit APCu (Fallback bleibt vorhanden)
- Optionales APCu-Rate-Limit für Requests ohne Score-Treffer
- Erweiterte und gehärtete Erkennungslogik in mehreren Kategorien
- Zusätzliche Einbindung und Erweiterung der Login-Guard-Überwachung
- Korrektur der Frontend-Admin-Erkennung: nicht mehr über Session-Gruppenstatus, sondern über den echten Accountstatus aus der Kundentabelle (customers_status = 0)

## Architekturvergleich Alt zu Neu

### 1. Kern-Guard Scanner
- Alt: Basislogik mit Pattern-Scoring und DB-Blocklisten
- Neu: zusätzliche Schutzmechanismen für Lastspitzen und parallele Requests, strukturierteres Housekeeping
- Aktuelle Datei:
  bx-codemaster/bx-security-monitor/src/includes/modules/bx_guard.php

### 2. Admin-Login-Wächter
- Alt: passiver Schutz für fehlgeschlagene Admin-Logins
- Neu: weiterhin passiv, erweitert um zusätzliche Login-Pfade und robuste Trigger
- Aktuelle Datei:
  bx-codemaster/bx-security-monitor/src/includes/modules/bx_admin_login_guard.php

### 3. Bootstrapping im Shop
- Aktivierung erfolgt über application_top_begin
- Datei:
  bx-codemaster/bx-security-monitor/src/includes/extra/application_top/application_top_begin/bx_security_bootstrap.php

### 4. Erfassung temporärer Admin-Sessions
- Erfassung/Aktualisierung in application_top_end
- Datei:
  bx-codemaster/bx-security-monitor/src/includes/extra/application_top/application_top_end/bx_security_session.php

### 5. Admin-Modul (Installation, Konfiguration, UI)
- Installation und Schema:
  bx-codemaster/bx-security-monitor/src/admin/includes/modules/system/bx_security_monitor.php
- Auswertung und Oberfläche:
  bx-codemaster/bx-security-monitor/src/admin/bx_security_monitor.php

## Datenbankschema und Verantwortlichkeiten

### msec_events
Zweck:
- Speicherung erkannter verdächtiger Requests und Login-Fehlversuche

Schreibende Komponenten:
- Scanner-Guard in includes/modules/bx_guard.php
- Login-Guard in includes/modules/bx_admin_login_guard.php

### msec_blocks
Zweck:
- aktive und abgelaufene IP-Sperren

Schreibende Komponenten:
- Scanner-Guard bei Schwellenwertüberschreitung
- Login-Guard bei zu vielen Admin-Fehlversuchen

### msec_whitelist
Zweck:
- dauerhaft vertrauenswürdige IPs

Schreibende Komponenten:
- Admin-Oberfläche in admin/bx_security_monitor.php

### msec_admin_sessions
Zweck:
- temporäre Vertrauensstellung aktiver Admin-Sessions

Schreibende Komponente im aktuellen Modulstand:
- includes/extra/application_top/application_top_end/bx_security_session.php

Wichtig für Betrieb und Fehlersuche:
- Diese Erfassung läuft im Shop-Hook application_top_end.
- Wenn erwartet wird, dass auch reine Admin-Backend-Aufrufe diese Tabelle kontinuierlich befüllen, muss zusätzlich ein passender Admin-Hook vorhanden sein.
- Im Ursprungspaket gab es dafür eine eigene Admin-Hook-Datei:
  security-monitor-for-modified-1.0.0/ADMIN_ORDNER/includes/extra/application_top/application_top_end/90_msec_admin_session.php

## Übernahme der alten Dokumentation in den neuen Stand

### Aus README_DE.txt übernommen
- Funktionsumfang und Grenzen des Moduls
- Datenschutz- und Betriebsaspekte
- Eignung und Vorsichtshinweise

### Aus BESCHREIBUNG_FUER_WEITERGABE.txt übernommen
- Download-/Forum-taugliche Kurzbeschreibung
- klare Abgrenzung, was enthalten ist und was nicht
- Hinweis auf lokale Datenspeicherung und Betreiberverantwortung

### Neu ergänzt in dieser Doku
- konkrete Codepfade und technische Verantwortlichkeiten
- Vergleich Alt/Neu auf Implementierungsebene
- Hinweise zur tatsächlichen Befüllung von msec_admin_sessions
- bekannte Lücken und empfohlene nächste Schritte

## Bekannte Abweichungen und offene Punkte

### 1. Admin-Session-Tracking im Backend
Der aktuelle src-Stand enthält bereits eine aktive Session-Schreiblogik über den Shop-Hook (application_top_end) in includes/extra/application_top/application_top_end/bx_security_session.php.

Auswirkung:
- msec_admin_sessions wird über diesen Hook befüllt und aktualisiert.

### 2. Login-Reparaturpfad
Der Repair-Pfad um login_admin.php wurde erweitert und in die Überwachung aufgenommen.

Auswirkung:
- fehlgeschlagene Reparatur-Logins können jetzt vom Login-Guard erfasst werden.

### 3. Legacy-Kontext modified
Das Modul arbeitet bewusst im Legacy-Stil von modified (xtc_db_query usw.), damit Integration und Kompatibilität erhalten bleiben.

### 4. Admin-Erkennung im Frontend
Ausgangslage:
- Im Frontend kann ein Admin über DEFAULT_CUSTOMERS_STATUS_ID_ADMIN mit einer anderen Kundengruppe arbeiten.
- Daher ist eine Admin-Erkennung über customers_status_id in der Session nicht verlässlich.

Umsetzung:
- Die Erkennung wurde auf DB-Basis umgestellt: maßgeblich ist der echte Accountstatus des eingeloggten Kundenkontos (customers_status = 0).
- Diese Logik wurde im Session-Tracking und im Login-Guard umgesetzt.

Auswirkung:
- Die Security-Entscheidung für Admin-Erkennung ist jetzt unabhängig von Frontend-Testgruppen und DEFAULT_CUSTOMERS_STATUS_ID_ADMIN.

## Änderungsmatrix (kompakt)

| Bereich | Ursprung 1.0.0 | Aktueller Stand src | Nutzen |
|---|---|---|---|
| Scanner-Engine | Basis-Scoring | ReDoS-Härtung, GET_LOCK, APCu-Rate-Limit | stabiler unter Last, weniger Race Conditions |
| Cleanup | zufallsbasiert | intervallbasiert mit APCu-Fallback | planbareres Housekeeping |
| Login-Guard | passiv | passiv plus erweiterte Pfadabdeckung | bessere Erfassung von Fehlversuchen |
| Frontend-Admin-Erkennung | über Session-Status interpretierbar | über echten Accountstatus aus DB (customers_status = 0) | korrekt trotz DEFAULT_CUSTOMERS_STATUS_ID_ADMIN |
| Admin-Session-Trust | vorhanden | vorhanden, aber primär über Shop-Hook | je nach Laufweg unterschiedliche Sichtbarkeit |
| Admin-UI | vorhanden | weiter ausgebaut | bessere Bedienung und Auswertung |

## Betriebs- und Qualitätshinweise
- Modul ist ein Sicherheitsbaustein, kein vollständiger Schutz gegen alle Angriffe.
- Regelmäßige Prüfung von Whitelist, Blockliste und manuellen Regeln ist notwendig.
- Bei Reverse Proxy oder CDN muss REMOTE_ADDR-Konzept betrieblich geprüft werden.
- Bei WordPress im gleichen Pfadraum sind Regeln und Schwellenwerte sorgfältig abzustimmen.

## Vorschlag für nächste Doku-Ausbaustufe
1. Release-Historie als Changelog pro Version (1.0.0, 1.1.0, weitere)
2. Testprotokoll mit reproduzierbaren Szenarien (Scanner, Login-Fehlversuch, Whitelist)
3. Betriebsleitfaden für Proxy/CDN-Umgebungen
4. Datenschutzvorlage für Verzeichnis von Verarbeitungstätigkeiten

## Status
- Dokument erstellt am 2026-07-11
- Basis: Vergleich Ursprungspaket und aktueller src-Code
- Ablage: docs/README.MD
