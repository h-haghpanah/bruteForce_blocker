from librouteros import connect
from decouple import config
from datetime import datetime, timedelta
from apps.utils.log import LogFile
import traceback
file_log = LogFile()


class MikrotikAPI:
    def __init__(self):
        self.router_ip = config("MIKROTIK_HOST", cast=str)
        self.router_api_port = config("MIKROTIK_API_PORT", cast=str, default=8728)
        self.router_user = config("MIKROTIK_USER", cast=str)
        self.router_pass = config("MIKROTIK_PASS", cast=str)
        self.api = connect(
                host=self.router_ip,
                port=self.router_api_port,
                username=self.router_user,
                password=self.router_pass,
            )

    def add_address_list(self, address_list, ip, comment="Blocked by script"):
        try:
            api_path = self.api.path('ip', 'firewall', 'address-list')
            api_path.add(
                list=address_list,
                address=ip,
                comment=comment
            )
        except Exception as e:
            error = f"Failed to add IP {ip} to address list {address_list}: {e}"
            print(error)
            file_log.error(traceback.format_exc(), e)
            return False
        return True

    def get_address_list_entries(self, address_list):
        try:
            api_path = self.api.path("ip", "firewall", "address-list")
            entries = list(api_path("print"))
            results = []
            for entry in entries:
                if entry.get("list") == address_list:
                    results.append({
                        "id": entry[".id"],
                        "address": entry["address"],
                        "comment": entry.get("comment", ""),
                        "created_at": datetime.strptime(entry.get("creation-time"), "%b/%d/%Y %H:%M:%S")
                    })
            return results
        except Exception as e:
            error = f"Mikrotik connection failed (get): {e}"
            print(error)
            file_log.error(traceback.format_exc(), e)
            return []

    def remove_address_list_entry(self, entry_id):
        try:
            api_path = self.api.path("ip", "firewall", "address-list")
            api_path.remove(entry_id)
            print(f"Entry {entry_id} removed successfully.")
            file_log.info(f"Entry {entry_id} removed successfully.")
            return True
        except Exception as e:
            print("Mikrotik connection failed (remove):", e)
            file_log.error(traceback.format_exc(), e)
            return False

    def remove_old_address_list_entries(self, address_list, older_than_minutes=20):
        entries = self.get_address_list_entries(address_list)
        threshold_time = datetime.now() - timedelta(minutes=older_than_minutes)
        for entry in entries:
            if entry["created_at"] < threshold_time:
                self.remove_address_list_entry(entry["id"])
