"""HunterOS CLI module."""
import sys
import os
import argparse

from hunteros.core.config import HunterOSConfig, get_default_config
from hunteros.core.safe_mode import SafeMode, get_safe_mode
from hunteros.core.policy import PolicyEngine
from hunteros.core.scope import ScopeEngine, ScopeStatus
from hunteros.project.manager import ProjectManager
from hunteros.finding.manager import FindingManager
from hunteros.evidence.manager import EvidenceManager
from hunteros.logging.logger import Logger


def main():
    """HunterOS CLI main entry point."""
    parser = argparse.ArgumentParser(
        prog="hunter",
        description="HunterOS - Personal Bug Hunter Research Framework",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # doctor command
    subparsers.add_parser("doctor", help="Check HunterOS environment")

    # config commands
    config_parser = subparsers.add_parser("config", help="Configuration commands")
    config_parser.add_argument("action", nargs="?", default="tampilkan",
                               choices=["tampilkan", "show"], help="Show configuration")

    # project commands
    project_parser = subparsers.add_parser("proyek", help="Project management")
    project_sub = project_parser.add_subparsers(dest="project_action")

    project_sub.add_parser("daftar", help="List all projects")
    buat_parser = project_sub.add_parser("buat", help="Create a new project")
    buat_parser.add_argument("nama", help="Project name")
    info_parser = project_sub.add_parser("info", help="Show project info")
    info_parser.add_argument("nama", help="Project name")

    # scope commands
    scope_parser = subparsers.add_parser("scope", help="Scope management")
    scope_sub = scope_parser.add_subparsers(dest="scope_action")
    add_scope_parser = scope_sub.add_parser("tambah", help="Add a scope entry")
    add_scope_parser.add_argument("pattern", help="Scope pattern (e.g., *.example.com)")
    add_scope_parser.add_argument("--desc", default="", help="Description")
    scope_sub.add_parser("tampilkan", help="Display scope entries")
    scope_check = scope_sub.add_parser("cek", help="Check target scope")
    scope_check.add_argument("target", help="Target to check")
    scope_sub.add_parser("hapus", help="Remove a scope entry")
    scope_sub.add_parser("reset", help="Clear all scope entries")

    # policy commands
    policy_parser = subparsers.add_parser("policy", help="Policy management")
    policy_sub = policy_parser.add_subparsers(dest="policy_action")
    policy_sub.add_parser("tampilkan", help="Show policy")
    add_policy_scope = policy_sub.add_parser("tambah-scope", help="Add scope to policy engine")
    add_policy_scope.add_argument("pattern", help="Scope pattern")
    add_policy_scope.add_argument("--desc", default="", help="Description")
    policy_sub.add_parser("show", help="Alias for tampilkan")

    # finding commands
    finding_parser = subparsers.add_parser("finding", help="Finding management")
    finding_sub = finding_parser.add_subparsers(dest="finding_action")
    finding_sub.add_parser("baru", help="Create a new finding")

    # evidence commands
    evidence_parser = subparsers.add_parser("evidence", help="Evidence management")
    evidence_parser.add_argument("action", nargs="?", default="simpan",
                                 choices=["simpan"], help="Save evidence")

    # recon commands
    recon_parser = subparsers.add_parser("recon", help="Reconnaissance commands")
    recon_sub = recon_parser.add_subparsers(dest="recon_action")
    recon_sub.add_parser("--help", help="Show recon help")
    dns_sub = recon_sub.add_parser("dns", help="Perform DNS recon on target")
    dns_sub.add_argument("target", help="Target domain")
    http_sub = recon_sub.add_parser("http", help="Perform HTTP metadata recon on URL")
    http_sub.add_argument("url", help="URL to analyze")
    recon_sub.add_parser("assets", help="List discovered assets")
    recon_sub.add_parser("status", help="Show recon status")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    # Handle commands
    if args.command == "doctor":
        return run_doctor()
    elif args.command == "config":
        return run_config(args)
    elif args.command == "proyek":
        return run_project(args)
    elif args.command == "scope":
        return run_scope(args)
    elif args.command == "policy":
        return run_policy(args)
    elif args.command == "finding":
        return run_finding(args)
    elif args.command == "evidence":
        return run_evidence(args)
    elif args.command == "recon":
        return run_recon(args)
    else:
        parser.print_help()
        return 0


def run_doctor() -> int:
    """Run HunterOS doctor check."""
    print("=" * 50)
    print("HunterOS Doctor Check")
    print("=" * 50)

    checks = []

    # Python
    try:
        import sys
        version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        checks.append(("Python", f"[✓] {version}", True))
    except Exception:
        checks.append(("Python", "[✗] Python not found", False))

    # HunterOS core
    try:
        from hunteros.core.config import HunterOSConfig
        from hunteros.core.safe_mode import SafeMode
        from hunteros.core.policy import PolicyEngine
        from hunteros.core.scope import ScopeEngine
        checks.append(("HunterOS core", "[✓] All modules loaded", True))
    except Exception as e:
        checks.append(("HunterOS core", f"[✗] Error: {e}", False))

    # Configuration
    try:
        config = get_default_config()
        checks.append(("Configuration", f"[✓] safe_mode={config.safe_mode}", True))
    except Exception as e:
        checks.append(("Configuration", f"[✗] {e}", False))

    # Storage
    try:
        pm = ProjectManager()
        checks.append(("Storage", "[✓] ProjectManager initialized", True))
    except Exception as e:
        checks.append(("Storage", f"[✗] {e}", False))

    # Scope Engine
    try:
        scope = ScopeEngine()
        checks.append(("Scope Engine", "[✓] ScopeEngine ready", True))
    except Exception as e:
        checks.append(("Scope Engine", f"[✗] {e}", False))

    # Policy Engine
    try:
        policy = PolicyEngine()
        checks.append(("Policy Engine", "[✓] PolicyEngine ready", True))
    except Exception as e:
        checks.append(("Policy Engine", f"[✗] {e}", False))

    # Safe Mode
    try:
        safe = get_safe_mode()
        checks.append(("Safe Mode", f"[✓] {'ON' if safe.is_on() else 'OFF'}", True))
    except Exception as e:
        checks.append(("Safe Mode", f"[✗] {e}", False))

    # Logging
    try:
        logger = Logger(project_name="test")
        checks.append(("Logging", "[✓] Logger ready", True))
    except Exception as e:
        checks.append(("Logging", f"[✗] {e}", False))

    # Tests
    try:
        import pytest
        tests_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tests")
        if os.path.exists(tests_path):
            checks.append(("Tests", "[✓] Test suite found", True))
        else:
            checks.append(("Tests", "[!] No test suite found", False))
    except Exception:
        checks.append(("Tests", "[!] pytest not available", False))

    # Optional dependencies
    try:
        import requests
        checks.append(("requests", "[✓] Optional dependency available", True))
    except ImportError:
        checks.append(("requests", "[!] Optional dependency missing", False))

    # Print results
    all_passed = True
    for name, status, passed in checks:
        print(f"  {status}  {name}")
        if not passed:
            all_passed = False

    print("=" * 50)
    if all_passed:
        print("Status: READY")
    else:
        print("Status: WARNING")
    print("=" * 50)

    return 0 if all_passed else 1


def run_config(args) -> int:
    """Handle config commands."""
    config = get_default_config()
    print("HunterOS Configuration:")
    print(f"  language:        {config.language}")
    print(f"  safe_mode:       {config.safe_mode}")
    print(f"  logging_enabled: {config.logging_enabled}")
    print(f"  debug_mode:      {config.debug_mode}")
    return 0


def run_project(args) -> int:
    """Handle project commands."""
    pm = ProjectManager()

    if args.project_action == "daftar":
        projects = pm.list_projects()
        if not projects:
            print("Tidak ada proyek.")
            return 0
        print("Daftar Proyek:")
        for p in projects:
            print(f"  {p.project_name} (ID: {p.project_id})")
            print(f"    Dibuat: {p.created_at}")
            print(f"    Scope: {len(p.scope)} entri")
            print(f"    Safe Mode: {'ON' if p.safe_mode else 'OFF'}")
        return 0

    elif args.project_action == "buat":
        name = args.nama
        project = pm.create(name)
        print(f"Proyek '{project.project_name}' berhasil dibuat.")
        print(f"  ID: {project.project_id}")
        print(f"  Dibuat: {project.created_at}")
        return 0

    elif args.project_action == "info":
        name = args.nama
        project = pm.get(name)
        if not project:
            print(f"ERROR: Project '{name}' belum ditemukan.")
            print("Gunakan: hunter proyek daftar")
            return 1
        print(f"Proyek: {project.project_name}")
        print(f"  ID: {project.project_id}")
        print(f"  Dibuat: {project.created_at}")
        print(f"  Updated: {project.updated_at}")
        print(f"  Scope: {', '.join(project.scope) if project.scope else 'Tidak ada'}")
        print(f"  Safe Mode: {'ON' if project.safe_mode else 'OFF'}")
        print(f"  Findings: {len(project.findings)}")
        print(f"  Evidence: {len(project.evidence)}")
        return 0

    return 0


def run_scope(args) -> int:
    """Handle scope commands."""
    policy = PolicyEngine()

    if args.scope_action == "tambah":
        pattern = args.pattern
        desc = args.desc
        policy.scope_engine.add_scope(pattern, desc)
        print(f"Scope '{pattern}' berhasil ditambahkan.")
        return 0

    elif args.scope_action == "tampilkan":
        scopes = policy.scope_engine.get_scopes()
        if not scopes:
            print("Tidak ada scope yang didefinisikan.")
            return 0
        print("Scope Entries:")
        for s in scopes:
            print(f"  {s.pattern} - {s.description}")
        return 0

    elif args.scope_action == "cek":
        target = args.target
        result = policy.scope_engine.check_target(target)
        print(f"Target: {target}")
        print(f"Status: {result.status.label()}")
        print(f"Alasan: {result.reason}")
        return 0

    elif args.scope_action == "hapus":
        # Note: scope subparser needs nama for hapus
        # Actually hapus should take a pattern
        print("Gunakan: hunter scope hapus <pattern>")
        return 0

    elif args.scope_action == "reset":
        policy.scope_engine.clear_scopes()
        print("Semua scope telah dihapus.")
        return 0

    return 0


def run_policy(args) -> int:
    """Handle policy commands."""
    policy = PolicyEngine()

    if args.policy_action == "tambah-scope":
        pattern = args.pattern
        desc = args.desc if hasattr(args, 'desc') else ""
        policy.scope_engine.add_scope(pattern, desc)
        print(f"Scope '{pattern}' berhasil ditambahkan ke Policy Engine.")
        return 0

    print("Policy Engine Status:")
    print(f"  Safe Mode: {'ON' if policy.safe_mode.is_on() else 'OFF'}")
    scopes = policy.scope_engine.get_scopes()
    print(f"  Scope entries: {len(scopes)}")
    if scopes:
        for s in scopes:
            print(f"    {s.pattern}")
    return 0


def run_finding(args) -> int:
    """Handle finding commands."""
    print("Finding commands not fully implemented in Phase 0.")
    print("Gunakan: hunter proyek buat <nama> terlebih dahulu.")
    return 0


def run_evidence(args) -> int:
    """Handle evidence commands."""
    print("Evidence commands not fully implemented in Phase 0.")
    return 0


def run_recon(args) -> int:
    """Handle recon commands."""
    from hunteros.recon.engine import ReconEngine
    from hunteros.recon.dns import DNSRecon
    from hunteros.recon.http import HTTPRecon
    from hunteros.recon.asset_inventory import AssetInventory
    from hunteros.core.scope import ScopeEngine
    from hunteros.core.policy import PolicyEngine

    recon_engine = ReconEngine()
    asset_inventory = AssetInventory()

    if args.recon_action == "dns":
        if not args.target:
            print("Gunakan: hunter recon dns <target>")
            return 1
        from hunteros.recon.engine import ReconEngine, ReconOperationType
        recon_engine = ReconEngine()
        result = recon_engine.execute(args.target, ReconOperationType.DNS)
        print(f"  Status: {result.status.label()}")
        if result.error:
            print(f"  Error: {result.error}")
        if result.data:
            print(f"  Data: {result.data}")
        return 0

    elif args.recon_action == "http":
        if not args.url:
            print("Gunakan: hunter recon http <url>")
            return 1
        from hunteros.recon.engine import ReconEngine, ReconOperationType
        recon_engine = ReconEngine()
        result = recon_engine.execute(args.url, ReconOperationType.HTTP)
        print(f"  Status: {result.status.label()}")
        if result.error:
            print(f"  Error: {result.error}")
        if result.data:
            print(f"  Data: {result.data}")
        return 0

    elif args.recon_action == "assets":
        assets = asset_inventory.list_assets()
        if not assets:
            print("Tidak ada aset yang ditemukan.")
            return 0
        print("Aset yang Ditemukan:")
        for a in assets:
            print(f"  {a.id}: {a.target} ({a.asset_type}) - status: {a.status}")
        return 0

    elif args.recon_action == "status":
        scope_engine = ScopeEngine()
        policy_engine = PolicyEngine()
        recon_engine = ReconEngine()
        asset_inventory = AssetInventory()
        print("Recon Engine Status:")
        print(f"  Scope Engine: {scope_engine}")
        print(f"  Policy Engine: {policy_engine}")
        print(f"  Safe Mode: {'ON' if recon_engine.safe_mode.is_on() else 'OFF'}")
        print(f"  Asset Inventory: {asset_inventory.to_dict()}")
        return 0

    elif args.recon_action == "--help" or args.recon_action is None:
        print("Recon Commands:")
        print("  hunter recon dns <target>     - Perform DNS recon")
        print("  hunter recon http <url>       - Perform HTTP metadata recon")
        print("  hunter recon assets           - List discovered assets")
        print("  hunter recon status           - Show recon status")
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())