# crypto-service-aes256gcm

Legt um das Paket aus dem Client (C1) eine zweite Schicht aus AES-256-GCM (C2) und nimmt sie beim Lesen wieder ab. Der Service speichert nichts und holt den Schlüssel bei jeder Anfrage neu vom Key-Service.
Ob jemand ein Paket bekommen darf, prüft er nicht, das macht vorher der Vault-Service.

Kotlin 2.4 · Ktor 3.6 · Java 21

## Endpoints

| Methode | Pfad | Zweck | Wer darf das aufrufen? |
|---|---|---|---|
| `POST` | `/internal/encrypt` | Legt die Schicht um `c1`, liefert `c2` | Vault-Service (`X-Service-Token`) |
| `POST` | `/internal/decrypt` | Nimmt die Schicht von `c2` ab, liefert `c1`. Jeder Fehler schreibt eine Zeile auf den Logger `audit` | Vault-Service (`X-Service-Token`) |
| `GET` | `/health` | `200`, wenn der Service läuft | alle |

Fehler kommen immer als `{"error":"<code>"}`:

| Status | Code | Wann |
|---|---|---|
| `400` | `bad_request` | Body, `userId`, `itemId`, `part`, `c1` oder `c2` ungültig |
| `401` | `unauthorized` | `X-Service-Token` fehlt oder ist falsch. Wird vor dem Body geprüft |
| `409` | `wrong_service` | Das Paket gehört zum ChaCha-Service |
| `413` | `payload_too_large` | Body über 256 KiB |
| `500` | `integrity_error` | Das Paket ist verändert oder gehört zu einem anderen Ziel |
| `500` | `internal_error` | Alles andere, auch Fehler des Key-Service |

Felder und Beispiele stehen im Repo `documentation` unter `api/crypto-service/`.

## Struktur

```text
src/main/kotlin/
├── Application.kt   Start: liest die Konfiguration, baut alle Teile, verbindet sie
├── AppConfig.kt     alle Umgebungsvariablen an einer Stelle
├── routes/          HTTP: Request lesen, Eingaben prüfen, Service aufrufen, antworten
├── services/        Fachlogik: Schlüssel holen, Schicht anlegen oder abnehmen
├── clients/         Aufrufe an den Key-Service, Dev-Stub dafür
├── models/          Requests/Responses, Fehlerklassen
├── security/        Paketformat TLX2, Base64
└── plugins/         Ktor-Einrichtung: JSON, Fehlerantworten
```

Ein Request läuft immer `routes` → `services` → `clients`.
Fehler werden als Exception geworfen (`models/ApiException.kt`) und zentral in `plugins/StatusPages.kt` beantwortet.
Das Interface `KeyProvider` gibt es, weil es zwei Varianten (Key-Service, Dev-Stub) und einen Fake für die Tests gibt.

Der Aufbau folgt der Anleitung `SERVICE-STRUKTUR.md` im `auth-service`.

## Lokal starten

```bash
VAULT_SERVICE_TOKEN=dev AES_SERVICE_TOKEN=dev ./gradlew run -Pdevelopment   # Port 8080
```

Im Dev-Modus darf `KEY_SERVICE_URL` fehlen, dann bekommt jeder Nutzer denselben Testschlüssel.
Ohne `-Pdevelopment` müssen alle Variablen gesetzt sein. Welche das sind, steht in `.env.example`.

## Tests

```bash
./gradlew test
```

Alle Tests laufen ohne Docker und ohne Key-Service, übersprungen wird nichts.

- `RoutesTest`, `CryptoEndpointsTest`: alle Endpoints mit jedem Fehlerfall, Antworten und Audit-Zeilen wörtlich, mit einem Fake für den `KeyProvider`
- `clients/KeyProviderTest`: der echte HTTP-Client gegen einen lokalen Stub
- `security/Tlx2Test`: Paketformat und Testvektoren

## Deploy

Ein Push auf den Branch `deploy` kopiert das Repo auf den Server, baut dort das Image und startet es neu (`.github/workflows/deploy.yml`).
Die `.env` liegt nur auf dem Server.

## Offen

- **Key-Service:** Er hat `POST /internal/keys/derive` noch nicht. Außerhalb des Dev-Modus antworten `encrypt` und `decrypt` deshalb mit `500 internal_error`.
- **Fehler des Key-Service:** Sie ergeben hier `500 internal_error`, im `auth-service` dagegen `502 upstream_error`. Das sollte einheitlich werden.
- **Port:** `docker-compose.yml` veröffentlicht den Port `7496`, laut Auftrag (`Crypto-Service-ChaCha.md`, Abschnitt 8) soll den Service nur der Vault-Service erreichen. Außerdem ist dort das Netz `auth-db-net` eingetragen, das niemand benutzt.
- **`gradlew`:** Die Datei ist im Repo nicht ausführbar, anders als in den anderen Services. Bis das korrigiert ist, geht es mit `sh gradlew …`.
