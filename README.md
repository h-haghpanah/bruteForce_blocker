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
git clone https://github.com/yourusername/bruteforce-blocker.git
cd bruteforce-blocker
