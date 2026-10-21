![Livemap](static/logo.png)

# Livemap

Livemap zeigt Zugriffe und Angriffe auf den eigenen Server live auf einer Weltkarte. Du siehst, woher sie kommen, wann sie kommen und was passiert. Die Software ist Open Source.

Die Seite ist nur nach dem Login erreichbar. Die Daten liegen in PostgreSQL.

## Voraussetzung

Python 3.11 oder neuer. Der Dienst braucht Leserechte auf das Fail2ban Log und die Nginx Access Logs.

Unter `data/` liegen diese Dateien:

* `world.geojson`, eine vereinfachte Weltkarte
* `dbip-country-lite.csv.gz` von [DB IP](https://db-ip.com/). Die kostenlose Länderdatenbank verlangt eine Namensnennung.
* `networks.csv` mit bekannten Netzbereichen großer Anbieter

Die Flaggen unter `static/flags/` stammen aus [flag icons](https://github.com/lipis/flag-icons) und stehen unter der MIT Lizenz.

## Start

Im Ordner mit der Compose Datei, Zugangsdaten nur in der `.env` daneben:

```bash
docker compose --env-file .env up -d --build
```

Ohne Docker, und ohne gesetzte Datenbankadresse, speichert Livemap in Sqlite:

```bash
python3 server.py
```

## Einstellungen

Alles über Umgebungsvariablen. Keine davon ist Pflicht.

| Variable | Bedeutung | Standard |
| --- | --- | --- |
| `LIVEMAP_HOST` | Adresse, an die der Dienst bindet | `127.0.0.1` |
| `LIVEMAP_PORT` | Port | `8791` |
| `LIVEMAP_F2B` | Pfad zum Fail2ban Log | `/var/log/fail2ban.log` |
| `LIVEMAP_NGINX` | Access Logs, durch Komma getrennt | `/var/log/nginx/access.log` |
| `LIVEMAP_NAME` | Angezeigter Name, sonst der Hostname | Hostname |
| `LIVEMAP_HOSTER` | Dateiname des Anbieterzeichens unter `static/marks/` | `ionos` |
| `LIVEMAP_HOSTER_NAME` | Name des Anbieters | `IONOS` |
| `LIVEMAP_LAT` und `LIVEMAP_LON` | Position des Servers | `52.52` und `13.405` |
| `LIVEMAP_OWN_IPS` | Eigene Adressen, zählen nicht als Angriff | leer |
| `LIVEMAP_ACTION_NETS` | Netze, die sperren und entsperren dürfen | lokal, WireGuard, eigene Adressen |
| `LIVEMAP_ACTION_JAILS` | Fail2ban Jails für den Rechtsklick | sshd und die Nginx Jails |

Beispiel für systemd:

```ini
[Service]
Environment=LIVEMAP_LAT=52.52
Environment=LIVEMAP_LON=13.405
Environment=LIVEMAP_NGINX=/var/log/nginx/access.log
ExecStart=/usr/bin/python3 /opt/livemap/server.py
```

Der Nutzer des Dienstes muss die Logs lesen dürfen. Unter Debian reicht dafür meist die Gruppe `adm`.

## Nginx

```nginx
server {
    server_name livemap.example.com;

    location /api/stream {
        proxy_pass http://127.0.0.1:8791;
        proxy_buffering off;
        proxy_read_timeout 3600s;
    }

    location / {
        proxy_pass http://127.0.0.1:8791;
    }
}
```

## Lizenz

MIT. Der Text steht in `LICENSE`.
