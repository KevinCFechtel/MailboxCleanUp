# MailboxCleanUp

Ein containerisierter Go-Dienst für regelmäßig ausgeführte IMAP-Archivierungs- und
Löschregeln. Führt [ImapDelete](https://github.com/KevinCFechtel/ImapDelete) und
[ImapArchive](https://github.com/KevinCFechtel/ImapArchive) zusammen.

**Standardmäßig werden keine Nachrichten verändert.** Erst nach manuellem
Entsperren **und** mit `dry_run: false` können Regeln Änderungen ausführen.
Vor dem ersten echten Lauf: Postfach sichern und Treffer im Dry-Run prüfen.

## Funktionen

- Mehrere IMAP-Konten mit explizit geordneten Regeln.
- Archivieren in bestehende IMAP-Ordner und endgültiges Löschen nach Alter.
- Fünffeld-Cron mit Zeitzone, begrenzter Laufzeit und ohne überlappende Jobs.
- Lokal mit **age/X25519** verschlüsselte Zugangsdaten; kein Klartext-Passwort in
  Konfiguration, Image oder Umgebungsvariablen.
- Einmaliges Entsperren nach jedem **Prozess-/Container-Neustart**. Danach laufen
  die Jobs ohne weitere Interaktion.
- Optionale Weboberfläche: anmelden, entsperren, sperren, Job starten und
  bereinigte Ergebnisse ansehen. Vollständig abschaltbar.
- CLI über privaten Unix-Socket sowie unabhängiger Einmalmodus.
- Verpflichtendes TLS mit Zertifikatsprüfung, kein Download von Mailinhalten.
- Optionale healthchecks.io-Erfolgsmeldung ausschließlich nach vollständig
  erfolgreichen Jobs; gesperrte/übersprungene Jobs senden keinen Ping.

## Architektur und Schlüssel

```text
Bitwarden / KeePassXC / anderer Passwortmanager
                    │ privater age-Schlüssel, einmal manuell
                    ▼
           CLI oder geschützte Weboberfläche
                    │
                    ▼
     Dienst hält Identität nur im Prozessspeicher
                    │ pro Job entschlüsseln
                    ▼
 lokale credentials.age ──► IMAP-Regeln über TLS
```

Die Anwendung ist absichtlich **nicht an einen Passwortmanager gekoppelt**.
Sie speichert weder dessen Master-Passwort noch einen Cloud-Zugriffstoken.
Nur den privaten age-Schlüssel in deinem Passwortmanager aufbewahren; alternativ
in einer lokalen KeePassXC-Datenbank. Ohne Schlüssel keine Wiederherstellung:
getrenntes, verschlüsseltes Backup einplanen.

Der Web-Zugangstoken ist ein **separates** Geheimnis. Er schützt die Oberfläche,
kann aber allein die IMAP-Zugangsdaten nicht entschlüsseln. Er liegt lokal in
einer zugriffsgeschützten Datei. Ein eingeloggter Benutzer kann einen bereits
entsperrten Dienst jedoch steuern.

## Schnellstart mit Docker Compose

Voraussetzungen: Docker mit Compose, SSH-Zugriff auf den Host und ein
Passwortmanager. Die Beispiele setzen eine Linux-NAS/einen Linux-Server voraus.
Das Image wird ausschließlich durch GitHub Actions gebaut und geprüft.
Zunächst muss ein Release-Tag wie `v1.0.0` erfolgreich veröffentlicht worden sein.
Bei privatem GHCR-Paket vorher mit einem entsprechend berechtigten Konto
anmelden. Eine lokale Go-Installation ist nicht erforderlich.

### 1. Konfiguration vorbereiten

```bash
mkdir -p config
cp examples/config.json config/config.json
docker compose pull
```

In `config/config.json` mindestens Server, Kontonamen, Quell-/Zielordner und
Aufbewahrungsfristen anpassen. Zunächst **`dry_run: true` beibehalten**.
Archivordner müssen bereits existieren.

### 2. Verschlüsselte Zugangsdaten erzeugen

```bash
docker run --rm -it --network none \
  --user "$(id -u):$(id -g)" \
  --mount "type=bind,src=$PWD/config,dst=/config" \
  ghcr.io/kevincfechtel/mailboxcleanup:latest credentials \
  --accounts personal \
  --output /config/credentials.age
```

Für mehrere Konten z. B. `--accounts personal,work`. Die Namen müssen mit der
Konfiguration übereinstimmen. Benutzername und Passwort werden verdeckt
abgefragt. Nach Möglichkeit ein separates, widerrufbares App-Passwort verwenden.

Der Befehl schreibt **nur verschlüsselte Zugangsdaten**. Er zeigt anschließend:

- den öffentlichen Empfänger `age1…`: für spätere Passwortrotation aufbewahren;
- den privaten Schlüssel `AGE-SECRET-KEY-…`: **jetzt im Passwortmanager sichern**.

Den privaten Schlüssel nicht in Dateien neben der Konfiguration, in Compose,
in Shell-Argumenten oder in Umgebungsvariablen hinterlegen. Terminal-Aufzeichnung
und Zwischenablage berücksichtigen. Der Erzeugungsbefehl darf den Schlüssel
einmal anzeigen; der laufende Dienst protokolliert ihn nie.

### 3. Web-Zugangstoken erzeugen

```bash
docker run --rm -it --network none \
  --user "$(id -u):$(id -g)" \
  --mount "type=bind,src=$PWD/config,dst=/config" \
  ghcr.io/kevincfechtel/mailboxcleanup:latest web-token --output /config/web-token
```

Diesen Token ebenfalls im Passwortmanager sichern. Er ist **nicht** der
age-Schlüssel.

Das Image läuft als UID/GID `65532`. Auf einem Linux-Host müssen die eingebundenen
Dateien für diesen Benutzer lesbar sein. Beispiel für das gerade angelegte,
ausschließlich diesem Dienst gehörende Verzeichnis:

```bash
sudo chown 65532:65532 config config/config.json config/credentials.age config/web-token
sudo chmod 0750 config
sudo chmod 0440 config/config.json
sudo chmod 0400 config/credentials.age config/web-token
```

NAS-ACLs/Benutzer-Mapping gegebenenfalls passend einrichten. Den Web-Token nicht
einfach weltweit lesbar machen: Der Dienst verweigert Token-Dateien mit
Gruppen-/Fremdrechten. Spätere Bearbeitung dieser Dateien benötigt entsprechende
Host-Administratorrechte.

### 4. Starten und Weboberfläche sicher erreichen

```bash
docker compose up -d
```

Compose veröffentlicht HTTP **nur auf `127.0.0.1` des Hosts**, nicht auf dessen
LAN-/Internet-Adresse. Zugriff vom eigenen Rechner per SSH-Tunnel:

```bash
ssh -N -L 18080:127.0.0.1:8080 benutzer@nas
```

Im Browser `http://localhost:18080` öffnen:

1. Mit dem **Web-Zugangstoken** anmelden.
2. Den **privaten age-Schlüssel** im Entsperrformular eingeben.
3. „Job jetzt starten“ verwenden und Dry-Run-Ergebnisse prüfen.

Das HTTP-Beispiel ist ausschließlich für diesen Loopback-/SSH-Ablauf gedacht.
Der Browser-Host und SSH-Endpunkt gehören zur Vertrauensgrenze. Eine Anmeldung
gilt 15 Minuten; **Abmelden sperrt den Dienst nicht** und beendet daher keine
Cron-Jobs.

Nach Prüfung für echte Änderungen `dry_run` auf `false` setzen und den Container
neu starten. Danach erneut entsperren. Keine Änderung der Konfiguration wird
ohne Neustart übernommen.

### HTTPS, VPN und Reverse Proxy

Für direkten Browserzugriff über das Netzwerk **HTTPS verwenden**, vorzugsweise
zusätzlich über VPN; die Oberfläche nicht öffentlich ins Internet stellen.

- Direkte TLS-Terminierung: `web.tls_cert_file` und `web.tls_key_file` angeben,
  `allow_insecure_http: false` und `secure_cookies: true` setzen.
- Reverse Proxy: TLS am vertrauenswürdigen Proxy, `secure_cookies: true`,
  HTTP intern ausdrücklich über `allow_insecure_http: true` erlauben. Den
  Backend-Port weder öffentlich noch für nicht vertrauenswürdige Container
  erreichbar machen. Originalen `Host` erhalten, damit Origin-Prüfung funktioniert.
- Bei HTTPS das Token-/Schlüssel-Formular **nur über HTTPS** aufrufen.
- Keine Proxy-/WAF-Konfiguration verwenden, die Request-Bodies protokolliert.
- Ein NAS-HTTPS-Proxy auf demselben Host kann den Loopback-Port nutzen. Ein Proxy
  in einem anderen Container erreicht ihn nicht über sein eigenes `127.0.0.1`;
  dafür ein dediziertes, isoliertes Docker-Netz konfigurieren.

Die Anwendung vertraut nicht automatisch `X-Forwarded-*`-Headern. Das Cookie-
Verhalten wird explizit konfiguriert. HTTP ohne sichere Cookies ist nur im
geschützten SSH-/Loopback-Szenario sinnvoll.

### Weboberfläche vollständig deaktivieren

```json
"web": {
  "enabled": false
}
```

Dann wird **kein TCP-Webserver gestartet**, kein Web-Token benötigt und es werden
keine TLS-Dateien gelesen. Optional auch die `ports`-Sektion in Compose entfernen.
Eine vollständige Beispielkonfiguration steht in
[`examples/config.cli-only.json`](examples/config.cli-only.json).

## CLI

Das minimale Image enthält keine Shell; den Befehl direkt ausführen:

```bash
docker exec -it mailboxcleanup mailboxcleanup unlock
docker exec mailboxcleanup mailboxcleanup status
docker exec mailboxcleanup mailboxcleanup run
docker exec mailboxcleanup mailboxcleanup lock
```

`unlock` liest den Schlüssel verdeckt vom Terminal. `--key-stdin` ermöglicht
optional eine direkte Pipe aus einem geeigneten lokalen Passwortmanager-
Werkzeug, ohne Schlüssel in Argumenten oder Umgebungsvariablen. Dabei niemals
Shell-Tracing (`set -x`) oder `echo SCHLÜSSEL` verwenden.

`run` startet asynchron; `status` liefert anschließend Ergebnis und Status.
`lock` entfernt die Identität und bricht einen aktiven Job ab. Bereits bestätigte
Änderungen können nicht zurückgenommen werden. Das Beenden laufender Operationen
erfolgt über Abbruch der IMAP-Verbindung; es gibt keine Transaktion/Rollback.

Alle Kontrollbefehle unterstützen `--socket PFAD`. Der Standard ist
`/run/mailboxcleanup/control.sock`, Dateimodus `0600`. Nur Prozesse mit Zugriff
auf diesen Socket dürfen den Dienst steuern. Docker-/Host-Administratoren sind
grundsätzlich vertrauenswürdig.

### Externer Cron und einmalige Ausführung

Ein externer Host-Cron kann `docker exec mailboxcleanup mailboxcleanup run`
aufrufen. Der dauerhafte, entsperrte Dienst bleibt dabei der Schlüsselhalter;
Cron benötigt keinen Schlüssel. Mit `"schedule": ""` den integrierten
Zeitplan deaktivieren oder ausschließlich den integrierten Cron verwenden.
Gleichzeitige Aufrufe werden abgewiesen, nicht aufgestaut.

Ein **unabhängiger** einmaliger Lauf ist ebenfalls möglich:

```bash
docker compose run --rm --no-deps mailboxcleanup \
  once --config /config/config.json
```

Dieser Prozess benötigt seine eigene Entsperrung. Ein vollständig unabhängiger,
unbeaufsichtigter Cron-Container könnte den Schlüssel nicht aus dem Speicher
eines anderen Prozesses übernehmen. Für den vereinbarten Ablauf deshalb
`serve` plus internen Cron oder `run` verwenden.

## Monitoring mit healthchecks.io

Die optionale Integration meldet **nur vollständig erfolgreiche Jobs**, nicht
die Erreichbarkeit des Containers. Nach einem Neustart bleibt der Dienst
gesperrt und sendet keine Pings, bis er entsperrt wurde und ein Job erfolgreich
durchgelaufen ist. Der Docker-Healthcheck ist davon unabhängig: Ein gesperrter
Dienst kann weiterhin als gesund gelten.

Konfiguration:

```json
"healthchecks": {
  "enabled": true,
  "url_file": "/config/healthchecks-url",
  "timeout": "5s",
  "ping_on_dry_run": false
}
```

1. Einen Check bei healthchecks.io oder einer selbst gehosteten Instanz anlegen.
2. Die **HTTPS-Erfolgs-URL mit Check-UUID** als einzige Zeile in
   `config/healthchecks-url` speichern, z. B.
   `https://hc-ping.com/00000000-0000-0000-0000-000000000001`.
   Keine `/start`-, `/fail`-, `/log`-, Exit-Code- oder Slug-URL verwenden.
3. Datei für den Container-Benutzer `65532:65532` lesbar machen und Dateimodus
   `0400` oder `0600` setzen. Die URL ist ein Geheimnis: Wer sie kennt, kann
   Erfolgsmeldungen vortäuschen. Nicht in Git, Logs oder Shell-Argumente schreiben.
4. Bei healthchecks.io denselben Cron-Zeitplan und dieselbe Zeitzone wie beim Job
   einstellen. Für `0 3 * * *`, `Europe/Berlin` und `job_timeout: "10m"` z. B.
   eine Grace Time von 15 Minuten vorsehen. Benachrichtigungskanäle dort aktivieren.
5. Dienst neu starten, entsperren und einen erfolgreichen Job ausführen.
   Prüfen, dass der Check aktiv überwacht wird und der Ping eingegangen ist.
   Ein neu angelegter, noch nicht gestarteter Check kann bis zum ersten Ping
   auf seine Aktivierung warten.

**„Schnell“ hängt vom Intervall ab:** Bei einem täglichen Job fällt eine
ausbleibende Entsperrung unter Umständen erst am nächsten Tag plus Grace Time
auf. Für eine kurze Erkennungszeit muss auch der Job entsprechend häufig laufen.
Die Anwendung sendet absichtlich keinen Start-, Sperr-, Fehler- oder
Lebenszeichen-Ping, der einen fehlenden erfolgreichen Job kaschieren könnte.

Verhalten:

- Ein HTTPS-POST mit aggregierten Zählern erst nach erfolgreicher Verarbeitung **aller Konten und
  Regeln inklusive Logout**. Auch ein erfolgreicher Lauf ohne Treffer zählt.
- Kein Ping beim Starten/Entsperren, für `status`, bei Sperre, Überschneidung,
  Timeout, Teilfehlern, überschrittenem Mengenlimit oder abgebrochenen Jobs.
- Dry-Runs senden standardmäßig **keinen** Erfolgsping. Für einen bewusst
  überwachten Testbetrieb `ping_on_dry_run: true` setzen.
- Manuell gestartete Jobs und `once` können ebenfalls einen Erfolgsping senden;
  für einen ausschließlich geplanten Check ggf. eine getrennte Konfiguration
  ohne Monitoring bei manuellen Einmalläufen verwenden.
- Nur aggregierte Treffer-/Aktionszahlen und ein Dry-Run-Kennzeichen im Request;
  keine Konten-/Regelnamen, Ordner, Mailinhalte, Schlüssel oder Fehlermeldungen.
  HTTP-Weiterleitungen werden nicht verfolgt; es gibt keine automatischen Retries.
- Scheitert die Erfolgsmeldung, wird der Lauf mit generischem Monitoring-Fehler
  als fehlgeschlagen angezeigt. Postfachänderungen bleiben bestehen. Bei einem
  Timeout kann der Server den Ping bereits empfangen haben, obwohl lokal keine
  Bestätigung eingetroffen ist.
- Die URL-Datei wird pro Job neu gelesen. URL-Rotation benötigt keinen Neustart;
  Konfigurationsänderungen dagegen schon.

Die Tests dieser Integration laufen über den vorhandenen GitHub-Actions-
Testschritt mit künstlichen Endpunkten. Es wird kein echter healthchecks.io-Check
aus dem CI angepingt.

### Job-Zähler im Ping

Der JSON-Body ist in den Ping-Details/Logs bei healthchecks.io einsehbar, z. B.:

```json
{"matched":42,"archived":30,"deleted":12,"dry_run":false}
```

- `matched`: Summe aller Treffer über Konten und Regeln.
- `archived` / `deleted`: Summe der UIDs in erfolgreich bestätigten Archivierungs-
  bzw. Löschbefehlen.
- `dry_run`: Kennzeichnet einen optional aktivierten Dry-Run-Ping. Dabei bleiben
  `archived` und `deleted` bei `0`, `matched` zeigt die gefundenen Treffer.

Die Zahlen sind **keine Anzahl eindeutiger Nachrichten**: Dieselbe Mail kann
in mehreren Regeln vorkommen, z. B. erst archiviert und dann gelöscht werden.
Andere Mailclients können parallel Nachrichten verändern; die Zähler sind
keine unabhängige Nachkontrolle der tatsächlich veränderten Nachrichten.
healthchecks.io stellt damit die Ping-Nutzlast bereit; automatische
Zeitreihengrafiken oder ein eigenes Statistik-Dashboard sind nicht implementiert.

## Konfiguration und Regelsemantik

[`examples/config.json`](examples/config.json) enthält ein vollständiges Beispiel.
Unbekannte Felder werden abgewiesen, damit Tippfehler nicht unbemerkt bleiben.

| Feld | Bedeutung |
|---|---|
| `credentials_file` | Lokal gespeicherte age-Datei; pro Job neu eingelesen, maximal 1 MiB |
| `schedule` | Fünffeld-Cron, standardmäßig `0 3 * * *`; `""` deaktiviert den integrierten Zeitplan |
| `timezone` | IANA-Zeitzone, standardmäßig `UTC`; Zeitzonendaten im Binary enthalten |
| `dry_run` | Standardmäßig `true`; nur suchen und zählen, Quelle read-only öffnen |
| `max_messages_per_rule` | Positive Grenze, standardmäßig 1000; bei Überschreitung keine Änderung durch diese Regel |
| `job_timeout` / `command_timeout` | Positive Go-Zeitspannen, standardmäßig `10m` / `30s` |
| `socket` | Privater lokaler Kontroll-Socket |
| `healthchecks.enabled` | Optionales Erfolgsmonitoring, standardmäßig `false` |
| `healthchecks.url_file` | Private Datei mit HTTPS-Erfolgs-URL und Check-UUID |
| `healthchecks.timeout` | Positiver HTTP-Timeout bis 1 Minute, standardmäßig `5s`; zusätzlich gilt der Job-Timeout |
| `healthchecks.ping_on_dry_run` | Dry-Run ebenfalls melden, standardmäßig `false` |
| `accounts[].name` | Eindeutiger Alias; derselbe Name wird in den verschlüsselten Zugangsdaten verwendet |
| `accounts[].server` | `host:port`, z. B. `imap.example.com:993` |
| `accounts[].tls_mode` | `tls` (implizit, meistens 993) oder verpflichtendes `starttls` (meistens 143) |
| `rules[].action` | `archive` oder `delete` |
| `rules[].mailbox` | Exakter IMAP-Quellordner, inklusive anbieterspezifischem Hierarchietrenner |
| `rules[].destination` | Bestehender Zielordner, nur für `archive` |
| `rules[].older_than_days` | 1–36500 Tage; Null/negative Werte werden abgewiesen |

### Was „älter als“ bedeutet

Wie in den Vorgängern wird IMAP `BEFORE` verwendet: Maßgeblich ist das
**INTERNALDATE-Datum**, nicht der `Date`-Header. Der Stichtag ist heute minus
Aufbewahrungstage, auf Kalendertage in der konfigurierten Zeitzone bezogen.
Nachrichten vom Stichtag selbst bleiben erhalten. Das sind keine rollierenden
24-Stunden-Fenster; IMAP vergleicht hierbei Datumsteile, keine exakten Zeitpunkte.

### Reihenfolge, Fehler und Schutzgrenzen

- Konten und Regeln werden in Konfigurationsreihenfolge ausgeführt.
- Regeln sehen die Ergebnisse früherer Regeln. Eine Nachricht kann daher
  innerhalb eines Jobs erst archiviert und anschließend durch eine spätere
  Regel gelöscht werden. Archivieren ändert ihr ursprüngliches INTERNALDATE nicht.
- Bei Fehlern stoppt das betreffende Konto; weitere Konten werden versucht.
- Die Mengengrenze gilt **pro Regel**, nicht pro Job. Bereits abgeschlossene
  Regeln werden bei späteren Fehlern nicht zurückgerollt.
- Änderungen werden in UID-Blöcken von maximal 200 angefordert. Nach einem
  Netzwerkfehler sind Teiländerungen möglich; vor einem erneuten Lauf prüfen.
- „Bestätigte UIDs“ zählt UIDs in erfolgreich bestätigten Befehlen, nicht eine
  unabhängig verifizierte Anzahl geänderter Nachrichten. Andere Mailclients
  können gleichzeitig Nachrichten bewegen oder löschen.
- Archivieren benötigt **MOVE**. Kein COPY-/EXPUNGE-Fallback.
- Löschen benötigt **UIDPLUS** und verwendet ausschließlich `UID STORE` plus
  `UID EXPUNGE` der ausgewählten UIDs. Kein globales `EXPUNGE`, kein `CLOSE`.
- Dry-Run kann auch ohne MOVE/UIDPLUS zählen; Unterstützung vor dem Echtbetrieb prüfen.
- Während der Sperre verpasste Jobs werden nicht nachgeholt. Entsperren löst
  keinen sofortigen Lauf aus; der nächste Cron-Termin oder „Job jetzt starten“ gilt.
- Cron-Zeitzonen und Sommerzeit beachten: nicht existierende Uhrzeiten werden
  übersprungen; UTC vermeidet lokale Sommerzeit-Sonderfälle.

## Zugangsdaten rotieren

Mit dem gespeicherten öffentlichen `age1…`-Empfänger eine neue Datei erzeugen:

```bash
docker run --rm -it --network none \
  --user "$(id -u):$(id -g)" \
  --mount "type=bind,src=$PWD,dst=/work" \
  ghcr.io/kevincfechtel/mailboxcleanup:latest credentials \
  --accounts personal \
  --recipient age1DEIN_OEFFENTLICHER_EMPFAENGER \
  --output /work/credentials.next.age
```

Alle konfigurierten Konten neu eingeben. Die neue Datei mit passenden
Dateirechten atomar als `config/credentials.age` installieren. Beispiel:

```bash
sudo chown 65532:65532 credentials.next.age
sudo chmod 0400 credentials.next.age
sudo mv credentials.next.age config/credentials.age
```

Die nächste Ausführung liest die neue Datei. Compose mountet dafür das ganze
Verzeichnis, nicht einen einzelnen Datei-Inode. Der private Schlüssel bleibt
gleich; bei Wechsel des Schlüssels den Dienst sperren und neu entsperren.

Web-Token separat rotieren: neue Token-Datei erzeugen, geschützt ersetzen und
Dienst neu starten. Dadurch verfallen alle Browser-Sitzungen und eine erneute
IMAP-Entsperrung ist erforderlich.

## Migration und Analyse der Vorgänger

Analysierte Stände:

- ImapDelete: `ffccead6cb32d3465ad12957f8c32a2377e7f367`
- ImapArchive: `2a729fe66252fe9df76d165c33be004e3ad5e345`
- CupNotifyer: CI-/Dependabot-Vorlage von `main` während der Implementierung.

Beide Vorgänger bestehen aus Go-Einstiegspunkt, JSON-Konfiguration, nahezu
identischem IMAP-Handler und optionalem gocron-Dienst. ImapDelete entfernt
Nachrichten, ImapArchive verschiebt sie. Die Zusammenführung übernimmt diese
Kernfunktionen, nicht die unsicheren Implementierungsdetails.

| Befund im Altcode | Umsetzung hier |
|---|---|
| `user`/`pass` in JSON, optional unverschlüsseltes IMAP | Verschlüsselter Credential-Container, zwingendes TLS |
| IMAP-Body/Envelope wird nur zur UID-Auswahl heruntergeladen | Nur UID-Suche, keine Nachrichteninhalte und keine implizite Lesemarkierung |
| Regel- und Mutationsfehler werden ignoriert, Treffer als Erfolg gezählt | Explizite Teilergebnisse, Fehlerstatus und Konto-Abbruch |
| Globales `EXPUNGE` und `CLOSE` beim Abmelden | Gezieltes UID EXPUNGE, ausschließlich LOGOUT |
| Archivierung arbeitet mit Sequenznummern und Bibliotheks-Fallback | Ausschließlich nativer UID MOVE |
| Endloses Warten ohne Signalbehandlung/Timeouts | Kontext-Abbruch, SIGTERM/SIGINT und kontrolliertes Beenden |
| HTTP-Logger kann nach Netzwerkfehler `nil` dereferenzieren; Antwort-Body bleibt offen | Strukturierte lokale, bereinigte JSON-Logs statt externer Log-Übermittlung |
| Container mit unfixiertem Basisimage und Shell-Entrypoint | Versionierter Multi-Stage-Build, statisches Nicht-Root-Image ohne Shell |

Alte JSON-Dateien werden **nicht direkt eingelesen**, insbesondere keine
Klartext-Passwörter. Manuelle Zuordnung:

| Alt | Neu |
|---|---|
| `server` + `port` | `accounts[].server` als `host:port` |
| `user` / `pass` | Interaktiver `credentials`-Befehl |
| `tls: true` | `tls_mode: "tls"` |
| `cronScheduleConfig` | `schedule` plus explizite `timezone` |
| Delete: `durations[].mailbox` / `duration` | Regel `action: "delete"`, `mailbox`, `older_than_days` |
| Archive: `sourceMailbox` / `destMailbox` / `duration` | Regel `action: "archive"`, `mailbox`, `destination`, `older_than_days` |
| `logurl` | Entfällt; strukturierte lokale Logs, kein automatischer externer Versand |
| `-runAsService` / `-configFile` | `serve --config …` bzw. `once --config …` |

Alte `duration: 0`-Regeln werden bewusst nicht übernommen: eine positive
Aufbewahrungsfrist ist erforderlich. Alte Klartext-Dateien und Backups
entsprechend behandeln und enthaltene Passwörter möglichst rotieren.

## Entwicklung und GitHub Actions

Tests, Build- und Sicherheitsprüfungen laufen in GitHub Actions, nicht auf
der NAS oder durch lokale Werkzeuginstallation. Der Workflow verwendet
die Go-Version aus `go.mod` und validiert außerdem die Compose-Konfiguration.

Die Tests verwenden künstliche Zugangsdaten und einen lokalen geskripteten
IMAP-Transport; kein echtes Postfach. Vor produktivem Löschen zusätzlich mit
einem eigenen Testkonto beim tatsächlichen Anbieter prüfen.

Die an CupNotifyer orientierte CI bietet:

- Formatprüfung, Race-Tests, `go vet`, Build und `govulncheck`;
- Dependency Review und CodeQL, soweit GitHub-Lizenz/Repositoreinstellungen dies erlauben;
- Container-Build und Trivy-Scan für **amd64 und arm64**, auch für Pull Requests;
- Veröffentlichung nach erfolgreichen Prüfungen nur für SemVer-Tags wie `v1.2.3`
  unter `ghcr.io/kevincfechtel/mailboxcleanup`;
- `latest` nur für stabile Releases, außerdem Versions- und SHA-Tags;
- Multiarch-Images mit SBOM und Build-Provenance;
- wöchentliche Sicherheitsläufe und Dependabot für Go, Actions und Docker;
- Actions und Trivy-Image auf konkrete Commit-/Digest-Stände fixiert.

Für **private Repositories** sind CodeQL, Dependency Review und SARIF-Upload
standardmäßig deaktiviert, weil dafür passende GitHub-Sicherheitsfunktionen
erforderlich sind. Sind diese verfügbar und aktiviert, die Repository-Variable
`ENABLE_GITHUB_SECURITY=true` setzen. Lokale Trivy-/Go-Scans bleiben auch ohne
diese Funktionen aktiv. Für GHCR-Publishing benötigt `GITHUB_TOKEN` die im
Workflow angegebene `packages: write`-Berechtigung und das Repository muss das
Paket veröffentlichen dürfen.

Es wurden keine IMAP-Zugangsdaten in GitHub Secrets hinterlegt; die CI greift
niemals auf ein echtes Postfach zu.

## Sicherheitsgrenzen

Siehe [`SECURITY.md`](SECURITY.md). Verschlüsselung schützt gespeicherte Dateien
und Backups, nicht einen kompromittierten entsperrten Host. Swap, Speicherabbilder,
Host-Zugriff, NAS-Backups, Browser und Passwortmanager sind Teil des Schutzkonzepts.
