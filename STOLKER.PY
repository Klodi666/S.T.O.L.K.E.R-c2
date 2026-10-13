#!/usr/bin/env python3
"""
STOLKER LAB - terminal scenario generator (safe simulator)
==========================================================
A terminal-only training tool. It generates ONE artifact per run: an
inert JSON file describing a simulated red-team scenario. It then asks
you where to save that file. Nothing else is written to disk.

HARD SAFETY INVARIANTS (enforced in code, see safety_* functions):
    * No executable files. Only `.json` may ever be written.
    * No shell metacharacters in any field. No subprocess, no sockets,
      no eval, no exec anywhere in this file.
    * Artifacts are inert JSON describing mock commands - the commands
      are never run and are prefixed with "(mock)" in the file.
    * Save path must be inside the user's home directory.
    * Generated filenames are validated and sanitized.

USAGE:
    python3 stolker.py                # interactive numbered menu
    python3 stolker.py --selftest     # run safety checks and exit
    python3 stolker.py --no-color     # disable ANSI colours

Author : DeepHat (Kindo)
Version: 2.0.0 (terminal scenario generator)
License: For isolated, authorized lab use only.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import sys
import time

# ===========================================================================
# ANSI STYLE
# ===========================================================================
class H:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"

    @classmethod
    def disable(cls):
        for n in dir(cls):
            if n.isupper():
                setattr(cls, n, "")


USE_COLOR = True


def col(text: str, colour: str) -> str:
    return text if not USE_COLOR else f"{colour}{text}{H.RESET}"


def clear() -> None:
    if sys.stdout.isatty():
        sys.stdout.write("\033[2J\033[H")
        sys.stdout.flush()


def hr(char: str = "─", width: int = 72, colour: str | None = None) -> None:
    line = char * width
    print(col(line, colour) if colour else line)


def status(msg: str, level: str = "INFO") -> None:
    ts = _dt.datetime.now().strftime("%H:%M:%S")
    tags = {
        "INFO":  ("[*]", H.CYAN),
        "OK":    ("[+]", H.GREEN),
        "WARN":  ("[!]", H.YELLOW),
        "ERR":   ("[x]", H.RED),
        "FILE":  ("[>]", H.MAGENTA),
        "SYS":   ("[~]", H.BLUE),
    }
    sym, colour = tags.get(level, ("[?]", H.WHITE))
    print(f"{col(f'[{ts}] {sym}', colour)} {msg}", flush=True)


def banner() -> None:
    art = r"""
   ███████╗████████╗ ██████╗ ██╗     ██╗  ██╗███████╗██████╗
   ██╔════╝╚══██╔══╝██╔═══██╗██║     ██║ ██╔╝██╔════╝██╔══██╗
   ███████╗   ██║   ██║   ██║██║     █████╔╝ █████╗  ██████╔╝
   ╚════██║   ██║   ██║   ██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗
   ███████║   ██║   ╚██████╔╝███████╗██║  ██╗███████╗██║  ██║
   ╚══════╝   ╚═╝    ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
"""
    print(col(art, H.GREEN))
    print(col("  terminal scenario generator  //  safe simulator  //  v2.0",
              H.BOLD + H.GREEN))
    print(col("  >> generates inert JSON training artifacts. no payloads. <<",
              H.YELLOW))
    print()


def pause(msg: str = "press ENTER to continue") -> None:
    try:
        input(col(f"  {msg}...", H.DIM))
    except (EOFError, KeyboardInterrupt):
        print()


def ask(prompt: str, default: str = "") -> str:
    suffix = col(f" [{default}]", H.DIM) if default else ""
    try:
        return input(col(f"  {prompt}", H.CYAN) + suffix + ": ").strip() or default
    except (EOFError, KeyboardInterrupt):
        print()
        return default


def ask_int(prompt: str, default: int, lo: int = 0, hi: int = 10**9) -> int:
    while True:
        raw = ask(prompt, str(default))
        try:
            v = int(raw)
        except ValueError:
            status("not a number, try again", "WARN")
            continue
        if not (lo <= v <= hi):
            status(f"must be between {lo} and {hi}", "WARN")
            continue
        return v


def ask_yn(prompt: str, default: bool = False) -> bool:
    d = "Y/n" if default else "y/N"
    try:
        raw = input(col(f"  {prompt} [{d}]: ", H.CYAN)).strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return default
    return default if not raw else raw.startswith("y")


# ===========================================================================
# SAFETY LAYER
# ===========================================================================
class SafetyError(Exception):
    pass


FORBIDDEN_EXT = (
    ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".scr", ".dll",
    ".msi", ".com", ".pif", ".jar", ".hta", ".lnk", ".sh",
    ".py", ".elf", ".bin", ".so", ".dylib", ".apk", ".app",
)

SHELL_METACHARS = (";", "|", "&", "`", "$", "(", ")", "<", ">", "\n", "\r")


def safety_check_text(s: str) -> str:
    """Reject control characters and shell metacharacters."""
    if not isinstance(s, str):
        raise SafetyError("field must be a string")
    if any(ord(c) < 0x20 and c != "\t" for c in s):
        raise SafetyError("field contains control characters")
    for ch in SHELL_METACHARS:
        if ch in s:
            raise SafetyError(f"field contains shell metacharacter {ch!r}")
    return s


def safety_check_filename(name: str) -> str:
    """Reject unsafe filenames and anything but .json."""
    if not name or "/" in name or "\\" in name or name in (".", ".."):
        raise SafetyError(f"unsafe filename: {name!r}")
    low = name.lower()
    for ext in FORBIDDEN_EXT:
        if low.endswith(ext):
            raise SafetyError(f"refused extension: {ext!r} (only .json allowed)")
    if not low.endswith(".json"):
        raise SafetyError("artifact filename must end with .json")
    return name


def safety_check_save_dir(path: str) -> str:
    """Save directory must be inside the user's home directory."""
    home = os.path.abspath(os.path.expanduser("~"))
    target = os.path.abspath(os.path.expanduser(path))
    if not (target == home or target.startswith(home + os.sep)):
        raise SafetyError(
            f"save path must be inside your home directory ({home})"
        )
    return target


def safety_no_forbidden_modules() -> None:
    """Ensure no process/socket/eval primitives are loaded."""
    for mod in ("subprocess", "ctypes", "socket", "telnetlib"):
        if mod in sys.modules:
            raise SafetyError(f"forbidden module loaded: {mod}")


# ===========================================================================
# SCENARIOS
# ===========================================================================
SCENARIOS = {
    "recon-entrop": {
        "Name": "Reconnaissance & Entropy Mapping",
        "Description": "Simulates passive fingerprinting and service enumeration.",
        "Tags": ["recon", "passive", "fingerprinting", "service-discovery"],
        "MockCommands": [
            "enumerate services on {LHOST}:{LPORT}",
            "fingerprint OS of {LHOST}",
            "map open ports on {LHOST}",
        ],
    },
    "web-ghost": {
        "Name": "Web Application Ghostwalk",
        "Description": "Simulates directory discovery and content analysis.",
        "Tags": ["web", "fuzzing", "directory-busting", "content-analysis"],
        "MockCommands": [
            "enumerate directories on http://{LHOST}:{LPORT}",
            "fuzz parameter 'id' on http://{LHOST}:{LPORT}",
            "review headers of http://{LHOST}:{LPORT}",
        ],
    },
    "net-cast": {
        "Name": "Network Lateral Movement Cast",
        "Description": "Simulates SMB enumeration and Kerberos relay mapping.",
        "Tags": ["active-directory", "lateral-movement", "smb", "kerberos"],
        "MockCommands": [
            "enumerate SMB shares on {LHOST}",
            "list Kerberos tickets for LAB\\lab_user",
            "query domain controllers near {LHOST}",
        ],
    },
    "cloud-drift": {
        "Name": "Cloud Infrastructure Drift",
        "Description": "Simulates cloud IAM and object-store enumeration.",
        "Tags": ["cloud", "aws", "k8s", "iam", "container"],
        "MockCommands": [
            "enumerate S3 buckets for account {LPORT}",
            "list Kubernetes pods in namespace {LHOST}",
            "enumerate IAM roles for account {LPORT}",
        ],
    },
}


# ===========================================================================
# ARTIFACT GENERATION
# ===========================================================================
def build_artifact(scenario_key: str, lhost: str, lport: int,
                   operator: str, lab_id: str) -> dict:
    """Build the inert JSON artifact. Does not write it yet."""
    sc = SCENARIOS[scenario_key]
    mock_cmds = [
        "(mock) " + c.replace("{LHOST}", lhost).replace("{LPORT}", str(lport))
        for c in sc["MockCommands"]
    ]
    return {
        "_type": "stolker-scenario-config",
        "_warning": (
            "This is an INERT training configuration. It is not executable "
            "and cannot run on any system. The commands below are descriptive "
            "strings only. They are never executed."
        ),
        "generated_at": _dt.datetime.now(_dt.timezone.utc)
            .strftime("%Y-%m-%dT%H:%M:%SZ"),
        "scenario_key": scenario_key,
        "scenario_name": sc["Name"],
        "scenario_description": sc["Description"],
        "tags": list(sc["Tags"]),
        "operator": operator,
        "lab_id": lab_id,
        "simulated_endpoint": {"host": lhost, "port": lport},
        "mock_commands": mock_cmds,
        "notes": [
            "Review each mock command and understand its purpose.",
            "These are descriptions of activity, not instructions to run.",
            "Document findings in your lab notebook.",
        ],
    }


def default_filename(scenario_key: str, operator: str) -> str:
    ts = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    base = re.sub(r"[^A-Za-z0-9_\-]", "_", f"{operator}_{scenario_key}")[:48]
    return f"stolker_{base}_{ts}.json"


def write_artifact(artifact: dict, save_dir: str, filename: str) -> str:
    """Write the JSON artifact to disk. The ONLY file this tool writes."""
    safety_check_filename(filename)
    save_dir = safety_check_save_dir(save_dir)
    os.makedirs(save_dir, exist_ok=True)
    full = os.path.join(save_dir, filename)
    # Defence in depth: final path must still be inside the save dir.
    if os.path.abspath(full) != os.path.join(save_dir, filename):
        raise SafetyError("resolved path escaped save directory")
    with open(full, "w", encoding="utf-8") as f:
        json.dump(artifact, f, indent=2, ensure_ascii=False)
    return full


# ===========================================================================
# SELF-TEST
# ===========================================================================
def run_selftest() -> list[tuple[str, bool, str]]:
    results: list[tuple[str, bool, str]] = []

    def check(name: str, fn, expect_error: bool = False):
        try:
            fn()
            results.append((name, not expect_error, "ok"))
        except Exception as e:
            results.append((name, expect_error, str(e)))

    # filename checks
    for good in ("a.json", "report_2024.json", "x-1.json"):
        check(f"filename accepts {good}",
              (lambda n=good: safety_check_filename(n)))
    for bad in ("a.exe", "b.bat", "c.ps1", "d.sh", "e.elf",
                "f.json.exe", "../g.json", "h/i.json"):
        check(f"filename rejects {bad}",
              (lambda n=bad: safety_check_filename(n)), expect_error=True)

    # save dir checks
    home = os.path.expanduser("~")
    check("save dir accepts ~",
          lambda: safety_check_save_dir(home))
    check("save dir accepts ~/subdir",
          lambda: safety_check_save_dir(os.path.join(home, "subdir")))
    for bad in ("/etc", "/tmp", "/root", "C:\\Windows"):
        check(f"save dir rejects {bad}",
              (lambda p=bad: safety_check_save_dir(p)), expect_error=True)

    # text checks
    check("text accepts plain sentence",
          lambda: safety_check_text("hello world"))
    for bad in ("a;b", "a|b", "a&b", "$(x)", "`x`", "a>b", "a\nb"):
        check(f"text rejects metachar {bad!r}",
              (lambda s=bad: safety_check_text(s)), expect_error=True)

    # module checks
    check("no forbidden modules loaded",
          safety_no_forbidden_modules)

    # artifact generation produces well-formed JSON with required fields
    def artifact_ok():
        a = build_artifact("recon-entrop", "127.0.0.1", 4444,
                           "lab_user", "default-lab")
        for key in ("_type", "_warning", "generated_at",
                    "scenario_key", "mock_commands"):
            if key not in a:
                raise AssertionError(f"missing key {key!r}")
        if not all(c.startswith("(mock)") for c in a["mock_commands"]):
            raise AssertionError("mock commands not prefixed")
        json.dumps(a)  # must be serialisable
    check("artifact builds and serialises", artifact_ok)

    # artifact build rejects metachars in operator
    check("artifact rejects metachar operator",
          (lambda: safety_check_text("bad;name")), expect_error=True)

    return results


def print_selftest() -> bool:
    print()
    hr("═")
    print(col("  SAFEGUARD SELF-TEST", H.BOLD + H.CYAN))
    hr("═")
    results = run_selftest()
    passed = sum(1 for _, ok, _ in results if ok)
    total = len(results)
    print()
    for name, ok, detail in results:
        mark = col("PASS", H.GREEN) if ok else col("FAIL", H.RED)
        print(f"  [{mark}] {name:<46} {col(detail, H.DIM)}")
    print()
    colour = H.GREEN if passed == total else H.RED
    print(col(f"  {passed}/{total} checks passed.", colour + H.BOLD))
    if passed == total:
        print(col("  [+] this tool cannot emit executable content", H.GREEN))
    else:
        print(col("  [x] some checks failed", H.RED))
    print()
    return passed == total


# ===========================================================================
# MENUS
# ===========================================================================
def menu_create_artifact() -> None:
    clear()
    banner()
    hr("═")
    print(col("  [1] CREATE TRAINING ARTIFACT", H.BOLD + H.GREEN))
    hr("═")
    print(col("  this generates ONE inert JSON file, then asks where to save it.",
              H.DIM))
    print()

    # 1. scenario
    print(col("  available scenarios:", H.BOLD))
    keys = list(SCENARIOS.keys())
    for i, k in enumerate(keys, 1):
        sc = SCENARIOS[k]
        print(f"    {col(f'[{i}]', H.GREEN)} {sc['Name']}")
        print(f"        {col(sc['Description'], H.DIM)}")
        print(f"        {col('tags: ' + ', '.join(sc['Tags']), H.DIM)}")
    print()

    choice = ask_int(f"select scenario (1-{len(keys)})", 1, 1, len(keys))
    scenario_key = keys[choice - 1]
    status(f"selected: {SCENARIOS[scenario_key]['Name']}", "OK")

    # 2. endpoint config
    print()
    print(col("  simulated endpoint (loopback only in this trainer):", H.BOLD))
    lhost = ask("host", "127.0.0.1")
    try:
        safety_check_text(lhost)
    except SafetyError as e:
        status(str(e), "ERR"); pause(); return
    if not re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", lhost):
        status("host must be an IPv4 address", "ERR"); pause(); return
    lport = ask_int("port", 4444, 1, 65535)

    # 3. metadata
    print()
    print(col("  metadata:", H.BOLD))
    operator = ask("operator / username", "lab_user")
    try:
        safety_check_text(operator)
    except SafetyError as e:
        status(str(e), "ERR"); pause(); return
    lab_id = ask("lab id", "default-lab")
    try:
        safety_check_text(lab_id)
    except SafetyError as e:
        status(str(e), "ERR"); pause(); return

    # 4. build artifact in memory
    print()
    status("building artifact in memory...", "INFO")
    try:
        artifact = build_artifact(scenario_key, lhost, lport, operator, lab_id)
    except Exception as e:
        status(f"build failed: {e}", "ERR"); pause(); return

    # show preview
    print()
    hr("─")
    print(col("  ARTIFACT PREVIEW", H.BOLD + H.CYAN))
    hr("─")
    preview = json.dumps(artifact, indent=2, ensure_ascii=False)
    for line in preview.splitlines():
        print(col("  " + line, H.DIM))
    hr("─")

    # 5. ask for save path
    print()
    print(col("  where to save this artifact?", H.BOLD + H.GREEN))
    print(col("  (must be inside your home directory)", H.DIM))
    default_dir = os.path.join(os.path.expanduser("~"), "Desktop",
                               "STOLKER_Artifacts")
    save_dir_in = ask("save directory", default_dir)
    try:
        save_dir = safety_check_save_dir(save_dir_in)
    except SafetyError as e:
        status(str(e), "ERR"); pause(); return

    default_name = default_filename(scenario_key, operator)
    filename = ask("filename", default_name)
    try:
        safety_check_filename(filename)
    except SafetyError as e:
        status(str(e), "ERR"); pause(); return

    if not ask_yn(f"write {os.path.join(save_dir, filename)}?", True):
        status("cancelled", "WARN"); pause(); return

    try:
        path = write_artifact(artifact, save_dir, filename)
    except SafetyError as e:
        status(str(e), "ERR"); pause(); return
    except OSError as e:
        status(f"write failed: {e}", "ERR"); pause(); return

    print()
    hr("─")
    print(col("  [+] artifact saved", H.BOLD + H.GREEN))
    hr("─")
    print(f"  {col('path:', H.CYAN)} {path}")
    print(f"  {col('size:', H.CYAN)} {os.path.getsize(path)} bytes")
    print(f"  {col('note:', H.CYAN)} inert JSON, not executable")
    print()
    pause()


def menu_list_artifacts() -> None:
    clear()
    banner()
    hr("═")
    print(col("  [2] LIST SAVED ARTIFACTS", H.BOLD + H.GREEN))
    hr("═")
    default_dir = os.path.join(os.path.expanduser("~"), "Desktop",
                               "STOLKER_Artifacts")
    d = ask("directory to scan", default_dir)
    try:
        d = safety_check_save_dir(d)
    except SafetyError as e:
        status(str(e), "ERR"); pause(); return
    if not os.path.isdir(d):
        status(f"no such directory: {d}", "WARN"); pause(); return
    files = sorted(f for f in os.listdir(d) if f.endswith(".json"))
    if not files:
        status("no .json artifacts found", "WARN"); pause(); return
    print()
    print(col(f"  {len(files)} artifact(s) in {d}", H.BOLD))
    hr("─")
    for f in files:
        full = os.path.join(d, f)
        size = os.path.getsize(full)
        mtime = _dt.datetime.fromtimestamp(os.path.getmtime(full)) \
            .strftime("%Y-%m-%d %H:%M")
        print(f"  {col(f, H.CYAN):<60} {size:>8} B  {col(mtime, H.DIM)}")
    print()
    pause()


def menu_view_artifact() -> None:
    clear()
    banner()
    hr("═")
    print(col("  [3] VIEW AN ARTIFACT", H.BOLD + H.GREEN))
    hr("═")
    path = ask("full path to .json artifact")
    if not path:
        return
    try:
        safety_check_filename(os.path.basename(path))
        safety_check_save_dir(os.path.dirname(path))
    except SafetyError as e:
        status(str(e), "ERR"); pause(); return
    if not os.path.isfile(path):
        status("no such file", "ERR"); pause(); return
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        status(f"could not read: {e}", "ERR"); pause(); return
    print()
    hr("─")
    print(col("  " + os.path.basename(path), H.BOLD + H.CYAN))
    hr("─")
    for line in json.dumps(data, indent=2, ensure_ascii=False).splitlines():
        print(col("  " + line, H.DIM))
    hr("─")
    pause()


def menu_help() -> None:
    clear()
    banner()
    hr("═")
    print(col("  [5] QUICK REFERENCE", H.BOLD + H.GREEN))
    hr("═")
    print()
    print(col("  WHAT THIS TOOL DOES", H.BOLD))
    print("    - generates ONE inert JSON scenario file per run")
    print("    - after generating, asks where to save that file")
    print("    - nothing else is written to disk")
    print()
    print(col("  WHAT THIS TOOL DOES NOT DO", H.BOLD))
    print("    - no executables, no batch files, no scripts")
    print("    - no network connections")
    print("    - no shell commands, no subprocess, no eval")
    print("    - no persistence, no stealth, no C2")
    print()
    print(col("  THE ARTIFACT", H.BOLD))
    print("    - a .json file describing a training scenario")
    print("    - mock commands are descriptive strings, never run")
    print("    - contains a _warning field saying exactly this")
    print()
    print(col("  SAFETY LIMITS", H.BOLD))
    print("    - only .json extensions are accepted")
    print("    - save paths must be inside your home directory")
    print("    - fields are checked for shell metacharacters")
    print()
    pause()


def main_menu() -> int:
    while True:
        clear()
        banner()
        hr("═")
        print(col("  MAIN MENU", H.BOLD + H.GREEN))
        hr("═")
        print(f"  {col('[1]', H.GREEN)} Create training artifact")
        print(f"  {col('[2]', H.GREEN)} List saved artifacts")
        print(f"  {col('[3]', H.GREEN)} View an artifact")
        print(f"  {col('[4]', H.GREEN)} Run safety self-test")
        print(f"  {col('[5]', H.GREEN)} Help / quick reference")
        print(f"  {col('[0]', H.GREEN)} Exit")
        print()
        try:
            choice = input(col("  select option: ", H.CYAN)).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0

        if choice == "1":
            menu_create_artifact()
        elif choice == "2":
            menu_list_artifacts()
        elif choice == "3":
            menu_view_artifact()
        elif choice == "4":
            clear(); banner(); print_selftest(); pause()
        elif choice == "5":
            menu_help()
        elif choice == "0":
            print()
            print(col("  [x] session terminated", H.RED))
            print()
            return 0
        else:
            status("unknown option", "WARN")
            time.sleep(0.5)


# ===========================================================================
# ENTRY POINT
# ===========================================================================
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="stolker.py",
        description="STOLKER LAB - terminal scenario generator (safe simulator).",
    )
    p.add_argument("--selftest", action="store_true",
                   help="run the safety self-test and exit")
    p.add_argument("--no-color", action="store_true",
                   help="disable ANSI colours")
    return p.parse_args()


def main() -> int:
    global USE_COLOR
    args = parse_args()
    if args.no_color or not sys.stdout.isatty():
        USE_COLOR = False
        H.disable()

    # refuse to run if a forbidden module is somehow loaded
    try:
        safety_no_forbidden_modules()
    except SafetyError as e:
        status(str(e), "ERR")
        return 2

    if args.selftest:
        ok = print_selftest()
        return 0 if ok else 2

    return main_menu()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        print(col("\n  [x] interrupted", H.RED))
        sys.exit(130)