# HunterOS v0.1 Foundation

## About

HunterOS is a personal bug hunter research, learning, and disclosure framework.
This is **Phase 0 Foundation** — the core modules that provide:

- Configuration management
- Safe Mode system
- Scope Engine
- Policy Engine
- Project Manager
- Finding Foundation
- Evidence Foundation
- Logger
- Hunter Doctor

## Safety First

HunterOS is designed with safety as the highest priority:

- **Safe Mode is ON by default**
- No destructive testing
- No DoS attacks
- No credential theft
- No persistence mechanisms
- No unauthorized access
- No secret exfiltration
- No testing against targets outside scope

**Scope is a technical constraint, not just documentation.**

## Quick Start

```bash
# Install
cd hunteros
pip install -e .

# Check environment
hunter doctor

# Create a project
hunter proyek buat example

# Check target scope
hunter scope cek api.example.com

# View configuration
hunter config tampilkan
```

## Commands

| Command | Description |
|---------|-------------|
| `hunter --help` | Show help |
| `hunter doctor` | Check environment |
| `hunter proyek buat <nama>` | Create project |
| `hunter proyek daftar` | List projects |
| `hunter proyek info <nama>` | Show project info |
| `hunter scope tampilkan` | Show scope entries |
| `hunter scope cek <target>` | Check target scope |
| `hunter policy tampilkan` | Show policy engine |
| `hunter config tampilkan` | Show configuration |

## Structure

```
hunteros/
├── hunteros/
│   ├── __init__.py
│   ├── cli.py              # CLI entry point
│   ├── core/
│   │   ├── config.py       # Configuration
│   │   ├── safe_mode.py    # Safe Mode controller
│   │   ├── scope.py        # Scope Engine
│   │   └── policy.py       # Policy Engine
│   │   ├── config.py       # Configuration
│   │   └── safe_mode.py    # Safe Mode controller
│   ├── project/            # Project Manager
│   │   ├── models.py       # Project data model
│   │   └── manager.py      # Project manager
│   ├── finding/            # Finding Foundation
│   │   ├── models.py       # Finding data model
│   │   └── manager.py      # Finding manager
│   ├── evidence/           # Evidence Foundation
│   │   ├── models.py       # Evidence data model
│   │   └── manager.py      # Evidence manager
│   └── logging/
│       └── logger.py       # Structured logger
├── tests/                  # Test suite
├── docs/                   # Documentation
├── examples/               # Example usage
└── README.md
```

## License

MIT