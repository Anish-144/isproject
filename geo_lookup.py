"""
geo_lookup.py — Lightweight IP-to-Location resolver for SOC Dashboard.

For local/private IPs (127.x, 10.x, 192.168.x, etc.) it generates
deterministic simulated coordinates so the demo map is always populated.
For real public IPs, it uses the free ip-api.com service (no key needed,
45 req/min). Results are cached for the process lifetime.
"""

import hashlib
import json
import urllib.request
import functools

# ── Well-known demo locations for simulated attacks ─────────────────────────
_DEMO_LOCATIONS = [
    {"country": "Russia",      "city": "Moscow",       "lat": 55.7558, "lon": 37.6173},
    {"country": "China",       "city": "Beijing",      "lat": 39.9042, "lon": 116.4074},
    {"country": "United States","city": "New York",     "lat": 40.7128, "lon": -74.0060},
    {"country": "Brazil",      "city": "São Paulo",    "lat": -23.5505,"lon": -46.6333},
    {"country": "Germany",     "city": "Berlin",       "lat": 52.5200, "lon": 13.4050},
    {"country": "India",       "city": "Mumbai",       "lat": 19.0760, "lon": 72.8777},
    {"country": "Nigeria",     "city": "Lagos",        "lat":  6.5244, "lon":  3.3792},
    {"country": "Iran",        "city": "Tehran",       "lat": 35.6892, "lon": 51.3890},
    {"country": "North Korea", "city": "Pyongyang",    "lat": 39.0392, "lon": 125.7625},
    {"country": "Romania",     "city": "Bucharest",    "lat": 44.4268, "lon": 26.1025},
    {"country": "Ukraine",     "city": "Kyiv",         "lat": 50.4501, "lon": 30.5234},
    {"country": "Vietnam",     "city": "Hanoi",        "lat": 21.0285, "lon": 105.8542},
    {"country": "Turkey",      "city": "Istanbul",     "lat": 41.0082, "lon": 28.9784},
    {"country": "Argentina",   "city": "Buenos Aires", "lat": -34.6037,"lon": -58.3816},
    {"country": "South Africa","city": "Johannesburg", "lat": -26.2041,"lon": 28.0473},
]

_PRIVATE_PREFIXES = ("127.", "10.", "192.168.", "172.16.", "172.17.",
                     "172.18.", "172.19.", "172.20.", "172.21.",
                     "172.22.", "172.23.", "172.24.", "172.25.",
                     "172.26.", "172.27.", "172.28.", "172.29.",
                     "172.30.", "172.31.", "0.0.0.0", "::1", "localhost")


def _is_private(ip: str) -> bool:
    return any(ip.startswith(p) for p in _PRIVATE_PREFIXES)


def _deterministic_demo(ip: str, event_hash: str = "") -> dict:
    """Pick a deterministic demo location from a hash of the IP + optional event context."""
    h = int(hashlib.md5((ip + event_hash).encode()).hexdigest(), 16)
    loc = _DEMO_LOCATIONS[h % len(_DEMO_LOCATIONS)].copy()
    # Add small jitter so overlapping markers spread out
    jitter = ((h >> 8) % 200 - 100) / 400.0
    loc["lat"] += jitter
    loc["lon"] += jitter
    return loc


@functools.lru_cache(maxsize=512)
def _lookup_public(ip: str) -> dict:
    """Query ip-api.com for a public IP. Free — 45 req/min, no key."""
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,city,lat,lon"
        req = urllib.request.Request(url, headers={"User-Agent": "SOC-Dashboard/1.0"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode())
        if data.get("status") == "success":
            return {
                "country": data.get("country", "Unknown"),
                "city":    data.get("city", "Unknown"),
                "lat":     data.get("lat", 0),
                "lon":     data.get("lon", 0),
            }
    except Exception:
        pass
    return _deterministic_demo(ip)


def geolocate(ip: str, event_hash: str = "") -> dict:
    """
    Return { country, city, lat, lon } for the given IP.

    * Private / local IPs → deterministic demo location (hash-based).
    * Public IPs → live lookup via ip-api.com (cached).

    `event_hash` is an optional string to diversify the demo location
    when the same private IP has multiple events (so markers spread out).
    """
    if _is_private(ip):
        return _deterministic_demo(ip, event_hash)
    return _lookup_public(ip)
