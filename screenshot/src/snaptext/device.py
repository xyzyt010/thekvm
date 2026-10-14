"""Device profiler: OS / arch / CPU / RAM / display server."""
from __future__ import annotations
import os
import platform
import sys


def get_device_profile() -> dict:
    try:
        import psutil
        ram_gb = round(psutil.virtual_memory().total / (1024 ** 3), 1)
        cores = psutil.cpu_count(logical=True) or 1
        phys = psutil.cpu_count(logical=False) or 1
    except Exception:
        ram_gb = 8.0
        cores = 4
        phys = 2
    machine = platform.machine() or "unknown"
    sys_name = platform.system().lower()  # windows | linux
    os_name = "windows" if sys_name.startswith("win") else ("linux" if sys_name.startswith("lin") else sys_name)
    return {
        "os": os_name,
        "os_version": platform.version(),
        "arch": machine,  # AMD64 / x86_64 / aarch64 / ARM64
        "cpu": platform.processor() or platform.uname().processor or "unknown",
        "cores_logical": cores,
        "cores_physical": phys,
        "ram_gb": ram_gb,
        "python": sys.version.split()[0],
        "display": detect_display_server(),
        "supported_v1": os_name in ("windows", "linux") and machine.lower() in ("amd64", "x86_64", "x86-64"),
    }


def detect_display_server() -> str:
    """Return one of: windows, x11, wayland, hyprland, xfce4, console/unknown."""
    if os.name == "nt":
        return "windows"
    # Hyprland sets HYPRLAND_* ; XFCE sets XDG_CURRENT_DESKTOP=xfce
    if os.environ.get("HYPRLAND_INSTANCE_SIGNATURE") or os.environ.get("HYPRLAND_CMD"):
        return "hyprland"
    desktop = (os.environ.get("XDG_CURRENT_DESKTOP") or "").lower()
    session = (os.environ.get("XDG_SESSION_TYPE") or "").lower()
    if "xfce" in desktop:
        return "xfce4" if session != "wayland" else "xfce4-wayland"
    if session == "wayland":
        return "wayland"
    if os.environ.get("WAYLAND_DISPLAY"):
        return "hyprland" if "hyprland" in desktop else "wayland"
    if os.environ.get("DISPLAY"):
        return "x11"
    return "unknown"


def arch_key(machine: str) -> str:
    m = machine.lower()
    if m in ("amd64", "x86_64", "x86-64", "x64"):
        return "x86_64"
    if m in ("aarch64", "arm64"):
        return "arm64"
    return m
