
# BruteForce Blocker & Mikrotik IP Blocker

A Python-based Brute Force attack detection system for web servers, integrated with Mikrotik routers to automatically block suspicious IPs. It also logs alerts to a SQLite database and optionally serves a web interface.

---

## Features

- **Real-time detection** of brute force attempts from web server logs (Apache/Nginx).
- **IP blocking** via Mikrotik firewall using address lists.
- **Alert logging** to both a log file and SQLite database.
- **Whitelist support** for trusted IPs and URLs.
- **Configurable time windows and thresholds**.
- **Web server** for monitoring and integration purposes.
- **Automated cleanup** of old blocked IP entries on Mikrotik.

---

## Installation

1. Clone the repository:

```bash
git clone https://github.com/h-haghpanah/BruteForce_Blocker.git
cd BruteForce_Blocker
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Configure environment variables in a `.env` file (see below).

4. Run the main script:

```bash
python main.py
```

This will start both the web server and the brute force detection scheduler in parallel threads.

---

## Usage

- The detector reads your web server access logs.
- It identifies IPs exceeding a maximum number of failed requests within a configurable time window.
- Detected IPs are optionally added to a Mikrotik firewall address list.
- Alerts are saved to a log file and a SQLite database.
- Old blocked IPs are automatically removed after a configurable duration.

---

## Environment Variables

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `LOG_FILE` | string | `access.log` | Path to the web server access log file. |
| `ACCESS_LOG_LINES` | int | `0` | Number of last lines to process from the log file. `0` means all lines. |
| `ALERT_LOG` | string | `bruteforce.log` | Path to store detected brute force alerts in JSON format. |
| `SAVE_ALERT_LOGS` | bool | `True` | Save detected alerts to the log file and database. |
| `TIME_INTERVAL_MINUTES` | int | `1` | Time window to check repeated attempts for brute force detection. |
| `MAX_ATTEMPTS` | int | `20` | Maximum allowed attempts within the time interval. |
| `MIKROTIK_SUBMIT_ADDRESS_LIST` | bool | `True` | Whether to automatically block IPs on Mikrotik router. |
| `MIKROTIK_HOST` | string | `172.16.5.1` | Mikrotik router IP address. |
| `MIKROTIK_API_PORT` | int | `8728` | Mikrotik API port. |
| `MIKROTIK_USER` | string | `admin` | Mikrotik API username. |
| `MIKROTIK_PASS` | string | `password` | Mikrotik API password. |
| `MIKROTIK_ADDRESS_LIST` | string | `BruteForceBlock` | Name of the Mikrotik address list for blocked IPs. |
| `MIKROTIK_BLOCK_TIME_MIN` | int | `60` | Duration (in minutes) to keep IPs blocked on Mikrotik. |
| `WHITE_LIST_IP` | comma-separated string | `` | IPs to exclude from detection and blocking. |
| `WHITE_LIST_URL` | comma-separated string | `` | URLs to exclude from detection. |
| `ACCESS_LOG_TIMEZONE` | string | `UTC` | Timezone of the web server logs (used for timestamp parsing). |
| `SQLITE_DB_FILE` | string | `bruteforce_alerts.db` | SQLite database file to store alert records. |
| `WEB_SERVER_HOST` | string | `0.0.0.0` | Host for the internal web server. |
| `WEB_SERVER_PORT` | int | `5000` | Port for the web server. |
| `WEB_SERVER_DEBUG` | bool | `True` | Enable Flask debug mode. |

---

## Project Structure

```
.
├── main.py                   # Entry point: starts web server and scheduler
├── apps/
│   ├── bruteforce_detector/
│   │   └── apache_nginx_bruteforce_detector.py  # Main detector logic
│   ├── utils/
│       └── log.py            # Custom logging utility
├── api/
│   └── mikrotik.py           # Mikrotik router API integration
├── web_server.py             # Flask app for web interface
├── requirements.txt
└── .env                      # Environment variables
```

---

## How It Works

1. **Log Parsing:**  
   Apache/Nginx logs are parsed using `apache_log_parser`. Both combined and common log formats are supported.

2. **Detection Logic:**  
   - Requests are grouped by `(IP, URL)`.
   - Attempts within the configured time interval are tracked using a deque.
   - When attempts exceed `MAX_ATTEMPTS`, an alert is generated.

3. **Mikrotik Integration:**  
   - Alerts trigger automatic addition of IPs to the configured Mikrotik address list.
   - Old entries are removed after `MIKROTIK_BLOCK_TIME_MIN` minutes.

4. **Alert Storage:**  
   - Alerts are saved to a log file (`ALERT_LOG`) in JSON format.
   - Alerts are also stored in SQLite (`SQLITE_DB_FILE`) for history and analytics.

5. **Web Server:**  
   - Optional Flask web interface runs in parallel for monitoring or integration.

---

## License

MIT License.  
