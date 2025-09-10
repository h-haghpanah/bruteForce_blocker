from apps.bruteforce_detector.apache_nginx_bruteforce_detector import BruteForceDetector
from api.mikrotik import MikrotikAPI
import schedule
import time
from decouple import config


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
        print("Dsdsdsds")
        alerts = self.detector.run()
        print(f"Run completed. Detected {len(alerts)} alerts.")
        if self.mikrotik:
            if alerts:
                for alert in alerts:
                    ip = alert["ip"]
                    if self.mikrotik.add_address_list(self.address_list, ip, comment="Blocked by BruteForceBlocker"):
                        print(f"Blocked IP: {ip} | Attempts: {alert['attempts']} | URL: {alert['url']}")
                self.mikrotik.remove_old_address_list_entries(self.address_list, older_than_minutes=self.mikrotik_block_time_min)


if __name__ == "__main__":
    job = MikrotikIPBlocker()
    schedule.every(10).seconds.do(job.run)
    print(job.time_interval_minutes)
    print("BruteForceBlocker started...")
    while True:
        schedule.run_pending()
        time.sleep(1)
