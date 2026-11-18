# Sicherheitsmodell

## Geschützte Daten und Vertrauensgrenzen

- Dauerhaft gespeicherte IMAP-Zugangsdaten sind mit age/X25519 verschlüsselt.
  Der private Schlüssel wird nicht von der Anwendung persistiert.
- Der Dienst startet nach jedem Prozess-/Container-Neustart gesperrt.
- Die Identität bleibt nach dem Entsperren im Prozessspeicher. Jeder Job liest
  die verschlüsselte Datei neu und entschlüsselt die Zugangsdaten für seinen Lauf.
- Sperren verwirft die Identität und signalisiert den Abbruch aktiver Jobs.
  Bereits ausgeführte Änderungen sind nicht rückgängig zu machen. Die aktive
  Operation kann bis zum Verbindungsabbruch noch serverseitig abgeschlossen werden.
- Go und die verwendeten Bibliotheken garantieren **keine vollständige
  Speicherlöschung**. Der Garbage Collector kann Kopien zurücklassen. Es gibt
  kein Versprechen, dass durch Sperren jedes frühere Byte sofort gelöscht wird.
- Es wird kein `mlock` erzwungen. Für „nicht dauerhaft auf dem Datenträger“
  müssen zusätzlich Swap deaktiviert oder zuverlässig verschlüsselt sowie
  Hibernation, Host-/VM-Snapshots und Speicherabbilder berücksichtigt werden.
  Das Programm deaktiviert Core Dumps nach Möglichkeit; Compose setzt zusätzlich
  ein Core-Limit von null.

Host-/Docker-Administratoren und Prozesse mit Zugriff auf den Unix-Socket können
den Dienst steuern. Root, ein kompromittierter Kernel oder beliebige
Codeausführung im entsperrten Prozess können auf Schlüssel und Passwörter
zugreifen. Dies wird nicht durch Verschlüsselung im Ruhezustand verhindert.

## Weboberfläche

- Im Code standardmäßig deaktiviert; im Compose-Beispiel für Loopback/SSH aktiviert.
- Separater zufälliger Zugangstoken, lokale Token-Datei nur für den Eigentümer lesbar.
- Serverseitige Sitzungen mit 15 Minuten absoluter Laufzeit, HttpOnly-Cookie,
  SameSite=Strict und konfigurierbarem Secure-Attribut. Keine lokale
  Browser-Speicherung des Schlüssels.
- Logout invalidiert die Browser-Sitzung, **nicht** die Entsperrung des Dienstes.
- CSRF-Token plus Go-Origin-/Fetch-Metadata-Prüfung für verändernde Requests.
- Globale Begrenzung von Login- und Entsperrversuchen, begrenzte Request-Größe,
  Header- und Lesezeitlimits. Die globale Begrenzung kann von anderen Nutzern
  desselben privaten Endpunkts ausgeschöpft werden.
- CSP ohne Skripte, Framing-Verbot, kein externer Inhalt, keine Analytics,
  kein Caching sensibler Antworten.
- Kein öffentlicher Internetbetrieb vorgesehen. VPN/SSH und HTTPS einsetzen.
  HTTP ist nur bei expliziter Freigabe oder numerischer Loopback-Bindung möglich.
- Das Beispiel verwendet wegen des SSH-Tunnels HTTP und `secure_cookies: false`.
  Bei HTTPS unbedingt `secure_cookies: true` setzen.
- TLS endet gegebenenfalls am Proxy; Backend und Proxy gehören dann zur
  Vertrauensgrenze. Request-Bodies dürfen dort nicht protokolliert werden.
- Passwortmanager-Autofill nur für die korrekte vertrauenswürdige URL verwenden.
  Browser-Erweiterungen und Zwischenablage können Geheimnisse einsehen.

## IMAP und Änderungen

- TLS >= 1.2 und normale Zertifikats-/Hostnamenprüfung. STARTTLS ist verpflichtend,
  wenn konfiguriert; es gibt keinen Klartext-Fallback und kein InsecureSkipVerify.
- Keine Mailinhalte, Betreffzeilen oder Absender werden heruntergeladen/protokolliert.
- Rohantworten des IMAP-Servers werden nicht in Fehlerberichte übernommen.
- Keine globalen EXPUNGE-/CLOSE-Operationen. Archivierung nur mit MOVE, Löschung
  nur mit UIDPLUS. Kein automatisches Erzeugen von Zielordnern.
- Dry-Run ist der Standard. Die positive Mengenobergrenze gilt je Regel.
- Mehrere Befehle/Regeln sind keine atomare Transaktion. Netzwerkfehler und
  parallele Mailclients können Teiländerungen bewirken. Backups bleiben nötig.
- Konfigurations- und Credential-Änderungen auf dem Host sind privilegiert.
  Ein Angreifer mit Schreibzugriff auf die Konfiguration kann Server und Regeln
  ändern. Die Konfiguration daher ebenfalls gegen unbefugtes Schreiben schützen.

## Container und Betrieb

- Optionales healthchecks.io-Monitoring sendet nur nach erfolgreichen Jobs einen
  HTTPS-POST mit aggregierten Treffer-/Archivierungs-/Löschzahlen und einem
  Dry-Run-Kennzeichen. Keine Rohfehler, Mailinhalte, Ordner oder Konten-Aliase
  werden übertragen. Die Gegenstelle erfährt zusätzlich IP-Adresse und Zeitpunkt
  eines Erfolgs; die Zähler lassen Rückschlüsse auf das Nachrichtenvolumen zu.
- Die Ping-URL wird als lokales Geheimnis behandelt und nicht protokolliert.
  HTTPS mit Zertifikatsprüfung ist verpflichtend; Redirects und Start-/Fehler-
  Endpunkte werden abgewiesen. Die Datei darf keine Gruppen-/Fremdrechte haben.
- Fehlende Pings erkennen Sperre/Stillstand nur nach dem bei healthchecks.io
  eingestellten Zeitplan und der Grace Time, nicht unmittelbar beim Neustart.

- Kein privater Schlüssel und keine echten Zugangsdaten im Image/Build-Kontext.
- Nicht-Root, read-only Root-Dateisystem, alle Capabilities entfernt,
  no-new-privileges, begrenzte Ressourcen.
- Kein Docker-Socket im Anwendungscontainer.
- Nur der private Kontroll-Socket liegt im RAM-Dateisystem. Der private
  age-Schlüssel wird auch dort nicht als Datei gespeichert.
- Der Healthcheck meldet einen gesperrten Dienst bewusst als gesund.
  Nach Wartung/Neustart Entsperrung und tatsächliche Job-Ergebnisse kontrollieren.
- Letztes Ergebnis und Browser-Sitzungen sind nur im Speicher. Logs enthalten
  Konten-/Regel-Aliase, Mengen und generische Fehler, keine Zugangsdaten.
  Auch diese Metadaten und Log-Aufbewahrung angemessen schützen.
- Sicherung der verschlüsselten Datei und getrennte Sicherung des privaten
  Schlüssels planen; Wiederherstellung testen. Bei Verdacht auf Schlüssel-
  oder Host-Kompromittierung zuerst IMAP-/App-Passwörter beim Anbieter widerrufen.

## Schwachstellen melden

Keine echten Schlüssel, Zugangsdaten oder Mailinhalte in öffentliche Issues,
CI-Logs oder Fehlerberichte aufnehmen. Falls im Repository verfügbar, private
GitHub Vulnerability Reports verwenden.
