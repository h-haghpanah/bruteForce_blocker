import geoip2.database


class IPTools:
    def __init__(self):
        self.db_path = "apps/utils/GeoLite2-Country.mmdb"

    def ip_location(self, ip):
        try:
            reader = geoip2.database.Reader(self.db_path)
            rec = reader.country(ip)
            reader.close()
            return rec.country.iso_code
        except Exception as e:
            print(e)
            return False
