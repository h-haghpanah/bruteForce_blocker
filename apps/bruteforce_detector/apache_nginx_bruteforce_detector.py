import apache_log_parser
from decouple import config
from datetime import datetime, timedelta
from collections import defaultdict, deque
import json
from zoneinfo import ZoneInfo
import sqlite3
import traceback
from apps.utils.log import LogFile

file_log = LogFile()


class BruteForceDetector:
    def __init__(self):
        self.log_file = config("LOG_FILE", cast=str, default="access.log")
        self.alert_log = config("ALERT_LOG", cast=str, default="bruteforce.log")
        self.time_window = timedelta(minutes=config("TIME_WINDOW", cast=int, default=1))
        self.time_interval_minutes = timedelta(minutes=config("TIME_INTERVAL_MINUTES", cast=int, default=1))
        self.max_attempts = config("MAX_ATTEMPTS", cast=int, default=20)
        self.address_list = config("MIKROTIK_ADDRESS_LIST", cast=str, default="BruteForceBlock")
        self.router_ip = config("MIKROTIK_HOST", cast=str)
        self.router_user = config("MIKROTIK_USER", cast=str)
        self.router_pass = config("MIKROTIK_PASS", cast=str)
        self.white_list_ip = set(config("WHITE_LIST_IP", default="").split(","))
        self.white_list_url = set(config("WHITE_LIST_URL", default="").split(","))
        self.save_alert_logs = config("SAVE_ALERT_LOGS", cast=bool, default=True)
        self.access_log_lines = config("ACCESS_LOG_LINES", cast=int, default=0)
        self.tz_name = config("ACCESS_LOG_TIMEZONE", default="UTC")
        self.timezone = ZoneInfo(self.tz_name)
        self.combined_parser = apache_log_parser.make_parser(
            '%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"'
        )
        self.clf_parser = apache_log_parser.make_parser(
            '%h %l %u %t "%r" %>s %b'
        )
        self.db_file = config("SQLITE_DB_FILE", cast=str, default="bruteforce.db")
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_file)
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                url TEXT,
                method TEXT,
                user_agent TEXT,
                attempts INTEGER,
                window_start TEXT,
                window_end TEXT,
                created_at TEXT
            )
        """)
        conn.commit()
        conn.close()

    def _save_to_db(self, alerts):
        conn = sqlite3.connect(self.db_file)
        c = conn.cursor()
        now = datetime.now(self.timezone).isoformat()
        for a in alerts:
            c.execute("""
                INSERT INTO alerts (ip, url, method, user_agent, attempts, window_start, window_end, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                a["ip"], a["url"], a.get("method"),
                a.get("user_agent"), a["attempts"],
                a["window_start"], a["window_end"],
                now
            ))
        conn.commit()
        conn.close()

    def parse_line(self, line):
        try:
            return self.combined_parser(line)
        except apache_log_parser.LineDoesntMatchException:
            return self.clf_parser(line)

    def run(self):
        attempts = defaultdict(lambda: deque())
        alerts = []
        now = datetime.now(self.timezone)

        with open(self.log_file, "r", encoding="utf-8") as f:
            if self.access_log_lines:
                last_lines = deque(f, maxlen=self.access_log_lines)
            else:
                last_lines = f
            for line in last_lines:
                try:
                    log = self.parse_line(line)
                    ip = log.get("remote_host")
                    url = log.get("request_url")
                    ts = log.get("time_received_isoformat")
                    method = log.get("request_method")
                    user_agent = log.get("request_header_user_agent")

                    if not (ip and url and ts):
                        continue

                    timestamp = datetime.fromisoformat(ts)
                    if timestamp.tzinfo is None:
                        timestamp = timestamp.replace(tzinfo=self.timezone)
                    else:
                        timestamp = timestamp.astimezone(self.timezone)
                    if not (now - self.time_interval_minutes <= timestamp <= now):
                        continue
                    key = (ip, url)
                    dq = attempts[key]
                    while dq and dq[0] < timestamp - self.time_interval_minutes:
                        dq.popleft()
                    dq.append(timestamp)
                    if ip in self.white_list_ip or url in self.white_list_url:
                        continue
                    if len(dq) > self.max_attempts:
                        alerts.append({
                            "ip": ip,
                            "url": url,
                            "method": method,
                            "user_agent": user_agent,
                            "attempts": len(dq),
                            "window_start": str(dq[0]),
                            "window_end": str(dq[-1])
                        })

                except Exception as e:
                    file_log.error(traceback.format_exc(), e)
                    print("Parse error:", e)
                    continue

        unique_alerts = {
            f"{a['ip']}_{a['url']}": a
            for a in alerts
        }.values()
        if self.save_alert_logs and unique_alerts:
            with open(self.alert_log, "a", encoding="utf-8") as f:
                for item in unique_alerts:
                    f.write(json.dumps(item, ensure_ascii=False) + "\n")
            self._save_to_db(unique_alerts)
        return unique_alerts
