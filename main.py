from apps.bruteforce_detector.apache_nginx_bruteforce_detector import BruteForceDetector
from api.mikrotik import MikrotikAPI
import schedule
import time
from decouple import config
from web_server import app
import threading
from apps.utils.log import LogFile

file_log = LogFile()


class MikrotikIPBlocker:
    def __init__(self):
        self.mikrotik_submit_address_list = config("MIKROTIK_SUBMIT_ADDRESS_LIST", cast=bool, default=True)
        if self.mikrotik_submit_address_list:
            self.mikrotik_block_time_min = config("MIKROTIK_BLOCK_TIME_MIN", cast=int, default=60)
            self.address_list = config("MIKROTIK_ADDRESS_LIST", cast=str, default="BruteForceBlock")
            self.mikrotik = MikrotikAPI()
        else:
            self.mikrotik = None
        self.detector = BruteForceDetector()
        self.time_interval_minutes = config("TIME_INTERVAL_MINUTES", cast=int, default=1)

    def run(self):
        alerts = self.detector.run()
        if self.mikrotik:
            if alerts:
                for alert in alerts:
                    ip = alert["ip"]
                    if self.mikrotik.add_address_list(self.address_list, ip, comment="Blocked by BruteForceBlocker"):
                        print(f"Blocked IP: {ip} | Attempts: {alert['attempts']} | URL: {alert['url']}")
                self.mikrotik.remove_old_address_list_entries(self.address_list, older_than_minutes=self.mikrotik_block_time_min)


def run_web_server():
    web_server_host = config("WEB_SERVER_HOST", cast=str, default="0.0.0.0")
    web_server_port = config("WEB_SERVER_PORT", cast=int, default=5000)
    web_server_debug = config("WEB_SERVER_DEBUG", cast=bool, default=True)
    app.run(host=web_server_host, port=web_server_port, debug=web_server_debug, use_reloader=False)


def run_scheduler():
    job = MikrotikIPBlocker()
    schedule.every(10).seconds.do(job.run)
    print("BruteForceBlocker started...")
    while True:
        schedule.run_pending()
        time.sleep(1)


if __name__ == "__main__":
    t1 = threading.Thread(target=run_web_server, daemon=True)
    t2 = threading.Thread(target=run_scheduler, daemon=True)
    t1.start()
    t2.start()
    while True:
        time.sleep(1)
