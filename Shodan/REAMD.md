# GL-Scout

A Shodan-powered reconnaissance tool for GL.iNet router enumeration and vulnerability surface mapping. Query, filter, and visualize global router deployments with an interactive web interface.

## Architecture
```
gl-scout/
├── gl_scout/
│   ├── __init__.py
│   ├── cli.py              # Entry point
│   ├── config.py           # Settings & constants
│   ├── shodan_client.py    # Shodan API wrapper
│   ├── filters.py          # Firmware version filtering
│   ├── models.py           # Data models (Router, ScanResult)
│   ├── exporters.py        # PNG generation
│   └── web/
│       ├── __init__.py
│       ├── app.py          # Flask/FastAPI app
│       ├── routes.py       # API endpoints
│       └── templates/
│           └── index.html  # Dashboard
├── data/
│   └── .gitkeep            # Cached scan results
├── exports/
│   └── .gitkeep            # Generated PNGs
├── tests/
├── pyproject.toml
├── README.md
└── .env.example
```

## Features

- **Shodan Integration** — Query GL.iNet routers by banner fingerprint, extract model and firmware metadata
- **Local Filtering** — Target specific firmware versions for vulnerability correlation
- **Interactive Web UI** — Real-time dashboard with filterable results
- **Export Visualizations**
  - 🗺️ Global heatmap (density by region)
  - 📍 Pin map (individual IP geolocation)
  - 📊 Bar charts (model/firmware distribution)

## Installation
```bash
git clone https://github.com/yourusername/gl-scout.git
cd gl-scout
pip install -e .
```

## Configuration
```bash
cp .env.example .env
```
```env
SHODAN_API_KEY=your_api_key_here
CACHE_TTL=3600
WEB_HOST=127.0.0.1
WEB_PORT=8080
```

## Usage

### CLI
```bash
# Full scan with default filters
gl-scout scan

# Target specific firmware versions
gl-scout scan --firmware "4.3.7,4.3.8,4.3.11"

# Export without launching web UI
gl-scout scan --export-only --output ./exports
```

### Web Interface
```bash
gl-scout serve
# → http://127.0.0.1:8080
```

**Dashboard Actions:**
| Action | Description |
|--------|-------------|
| Filter | Narrow results by model, firmware, country |
| Export Heatmap | Download PNG of global density map |
| Export Pins | Download PNG with individual IP markers |
| Export Charts | Download PNG bar chart of distributions |

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/routers` | List all discovered routers |
| GET | `/api/routers?firmware=4.3.7` | Filter by firmware |
| GET | `/api/stats` | Aggregated statistics |
| GET | `/api/export/heatmap` | PNG heatmap download |
| GET | `/api/export/pins` | PNG pin map download |
| GET | `/api/export/chart` | PNG bar chart download |

## Data Model
```python
@dataclass
class Router:
    ip: str
    port: int
    model: str           # e.g., "GL-MT3000"
    firmware: str        # e.g., "4.3.7"
    latitude: float
    longitude: float
    country: str
    city: str
    asn: str
    last_seen: datetime
```

## Example Output
```json
{
  "total": 12847,
  "filtered": 3421,
  "by_model": {
    "GL-MT3000": 1823,
    "GL-AXT1800": 892,
    "GL-MT2500": 706
  },
  "by_firmware": {
    "4.3.7": 1245,
    "4.3.8": 967,
    "4.3.11": 1209
  },
  "by_country": {
    "US": 2341,
    "DE": 1122,
    "CN": 891
  }
}
```

## Dependencies

- `shodan` — Shodan API client
- `fastapi` + `uvicorn` — Web framework
- `folium` — Interactive maps
- `matplotlib` / `plotly` — Chart generation
- `pillow` — PNG export
- `pydantic` — Data validation
- `python-dotenv` — Configuration

## Responsible Use

This tool is intended for authorized security research only. Ensure you have appropriate permissions before scanning or probing any discovered hosts. The author is not responsible for misuse.

## License

MIT

## Author

Aleksa — [DC381](https://dc381.org)