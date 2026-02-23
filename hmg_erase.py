#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
hmg_erase.py — Borrado seguro HMG Infosec Standard 5

Frontend  : Python + curses  (selección múltiple de discos, exclusión Live USB, confirmación)
Motor     : nwipe             (borrado certificado, paralelo, TUI propia, log)

Estándares:
  IS5 Baseline : 1 pasada aleatoria         → nwipe --method=random
  IS5 Enhanced : 3 pasadas 0x00/0xFF/random → nwipe --method=is5enh

Uso: sudo python3 hmg_erase.py
     apt install nwipe
"""

import curses
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Set, Tuple

# ──────────────────────────────────────────────────────────────────────────────
# Constantes
# ──────────────────────────────────────────────────────────────────────────────

VERSION = "3.0.0"
LOG_DIR = "/tmp"

LIVE_MOUNT_POINTS = {
    "/lib/live/mount/medium",
    "/run/live/medium",
    "/run/initramfs/live",
    "/run/live/rootfs",
    "/media/cdrom", "/media/cdrom0", "/cdrom",
}

NWIPE_METHODS = {
    "baseline": "random",    # 1 pasada PRNG — equivalente IS5 Baseline
    "enhanced": "is5enh",    # implementación nativa IS5 Enhanced (nwipe 0.30+)
}

STANDARD_LABELS = {
    "baseline": "HMG IS5 Baseline  (1 pasada aleatoria)",
    "enhanced": "HMG IS5 Enhanced  (3 pasadas: 0x00 / 0xFF / aleatorio)",
}

# ──────────────────────────────────────────────────────────────────────────────
# Estructuras de datos
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class Disk:
    name: str
    path: str
    size_bytes: int
    size_str: str
    model: str
    transport: str
    disk_type: str        # HDD / SSD / NVMe SSD
    is_excluded: bool = False
    exclusion_reason: str = ""


@dataclass
class NwipeCaps:
    version: str
    has_is5enh: bool      # --method=is5enh disponible
    has_logfile: bool     # --logfile disponible
    has_nowait: bool      # --nowait disponible


@dataclass
class EraseResult:
    disks: List[Disk]
    standard: str
    start_time: datetime
    end_time: datetime
    success: bool
    log_path: str
    error: str = ""


# ──────────────────────────────────────────────────────────────────────────────
# Utilidades
# ──────────────────────────────────────────────────────────────────────────────

def check_root() -> None:
    if os.geteuid() != 0:
        print("ERROR: ejecute como root →  sudo python3 hmg_erase.py")
        sys.exit(1)


def require_nwipe() -> NwipeCaps:
    """Comprueba que nwipe está instalado. Aborta si no lo está."""
    if not shutil.which("nwipe"):
        print(
            "\nERROR: nwipe no está instalado.\n"
            "Instálelo con:  apt install nwipe\n"
        )
        sys.exit(1)

    try:
        r = subprocess.run(["nwipe", "--version"],
                           capture_output=True, text=True, timeout=5)
        version = (r.stdout + r.stderr).strip().splitlines()[0]
    except Exception:
        version = "desconocida"

    try:
        r = subprocess.run(["nwipe", "--help"],
                           capture_output=True, text=True, timeout=5)
        help_text = r.stdout + r.stderr
    except Exception:
        help_text = ""

    caps = NwipeCaps(
        version    = version,
        has_is5enh = "is5enh"   in help_text,
        has_logfile= "--logfile" in help_text,
        has_nowait = "--nowait"  in help_text,
    )
    logging.info(
        f"nwipe {version}  is5enh={caps.has_is5enh}  "
        f"logfile={caps.has_logfile}  nowait={caps.has_nowait}"
    )
    return caps


def format_size(n: int) -> str:
    if n <= 0:
        return "0 B"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def format_duration(s: float) -> str:
    s = max(0.0, s)
    if s < 60:   return f"{s:.0f}s"
    if s < 3600: return f"{s/60:.0f}m {s%60:.0f}s"
    h = int(s // 3600)
    return f"{h}h {int((s % 3600) // 60)}m"


def get_log_path() -> str:
    return f"{LOG_DIR}/hmg_erase_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"


def setup_logging(log_path: str) -> None:
    logging.basicConfig(
        filename=log_path, level=logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    logging.info(f"=== HMG IS5 Erasure Tool v{VERSION} ===")


# ──────────────────────────────────────────────────────────────────────────────
# Detección de discos y exclusión del Live USB
# ──────────────────────────────────────────────────────────────────────────────

def _parent_device(dev: str) -> str:
    p = re.sub(r"p\d+$", "", dev)
    p = re.sub(r"\d+$",  "", p)
    return p if p != dev else dev


def get_excluded_devices() -> Set[str]:
    excluded: Set[str] = set()

    def add(dev: str) -> None:
        excluded.add(dev)
        parent = _parent_device(dev)
        if parent != dev:
            excluded.add(parent)

    try:
        with open("/proc/mounts") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 2:
                    continue
                dev, mp = parts[0], parts[1]
                if not dev.startswith("/dev/"):
                    continue
                if mp in ("/", "/boot", "/boot/efi", "/efi") \
                        or mp in LIVE_MOUNT_POINTS:
                    add(dev)
                    logging.info(f"Excluido: {dev}  montado en {mp}")
    except Exception as e:
        logging.warning(f"No se pudo leer /proc/mounts: {e}")

    try:
        with open("/proc/cmdline") as f:
            for m in re.finditer(r"root=(/dev/\S+)", f.read()):
                add(m.group(1))
    except Exception:
        pass

    return excluded


def _dev_has_mounts(dev: dict) -> bool:
    mp = dev.get("mountpoint") or ""
    if mp and mp not in ("[SWAP]", ""):
        return True
    for child in dev.get("children") or []:
        if _dev_has_mounts(child):
            return True
    return False


def get_disks() -> List[Disk]:
    try:
        r = subprocess.run(
            ["lsblk", "-J", "-b", "-o",
             "NAME,SIZE,TYPE,TRAN,MODEL,MOUNTPOINT,ROTA"],
            capture_output=True, text=True, check=True,
        )
        data = json.loads(r.stdout)
    except Exception as e:
        logging.error(f"lsblk falló: {e}")
        return []

    excluded = get_excluded_devices()
    disks: List[Disk] = []

    for dev in data.get("blockdevices", []):
        if dev.get("type") != "disk":
            continue
        name = dev.get("name", "")
        if not name or name.startswith(("loop", "dm-", "sr", "fd")):
            continue

        path       = f"/dev/{name}"
        size_bytes = int(dev.get("size") or 0)
        model      = (dev.get("model") or "Modelo desconocido").strip()
        transport  = (dev.get("tran")  or "desconocido").lower()
        rotational = str(dev.get("rota", "1")) == "1"

        if "nvme" in name or transport == "nvme":
            disk_type = "NVMe SSD"
        elif not rotational:
            disk_type = "SSD"
        else:
            disk_type = "HDD"

        has_mounts  = _dev_has_mounts(dev)
        is_boot     = path in excluded
        is_excluded = is_boot or has_mounts

        if is_boot:
            reason = "Dispositivo de arranque / Live USB"
        elif has_mounts:
            reason = "Particiones montadas (desmonte primero)"
        else:
            reason = ""

        disk = Disk(
            name=name, path=path, size_bytes=size_bytes,
            size_str=format_size(size_bytes), model=model,
            transport=transport.upper(), disk_type=disk_type,
            is_excluded=is_excluded, exclusion_reason=reason,
        )
        disks.append(disk)
        logging.info(
            f"Disco: {path}  {disk.size_str}  {model}  "
            f"[{disk_type}]  excluido={is_excluded}"
        )

    return disks


# ──────────────────────────────────────────────────────────────────────────────
# Motor de borrado — nwipe
# ──────────────────────────────────────────────────────────────────────────────

def run_nwipe(disks: List[Disk], standard: str,
              caps: NwipeCaps, log_path: str) -> Tuple[bool, str]:
    """
    Lanza nwipe en primer plano con su propia TUI de progreso.
    Borra todos los discos en paralelo en un solo comando.
    Asume que curses está desactivado (curses.endwin() ya llamado).
    """
    method = NWIPE_METHODS[standard]
    cmd    = ["nwipe", "--autonuke", f"--method={method}", "--verify=last"]

    if caps.has_logfile:
        cmd.append(f"--logfile={log_path}")
    if caps.has_nowait:
        cmd.append("--nowait")

    for disk in disks:
        cmd.append(disk.path)

    sep = "=" * 62
    print(f"\n{sep}")
    print(f"  nwipe  [{STANDARD_LABELS[standard]}]")
    print(f"  Discos ({len(disks)}):")
    for disk in disks:
        print(f"    • {disk.path}  {disk.size_str}  {disk.model}  [{disk.disk_type}]")
    print(f"{sep}\n")

    logging.info(f"Ejecutando: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd)
        if result.returncode == 0:
            return True, ""
        return False, f"nwipe salió con código {result.returncode}"
    except Exception as e:
        return False, str(e)


# ──────────────────────────────────────────────────────────────────────────────
# TUI con curses — helpers
# ──────────────────────────────────────────────────────────────────────────────

C_HEADER, C_SELECTED, C_EXCLUDED = 1, 2, 3
C_NORMAL, C_WARNING,  C_SUCCESS  = 4, 5, 6
C_ERROR,  C_DIM,      C_MARKED   = 7, 8, 9


def _init_colors() -> None:
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(C_HEADER,   curses.COLOR_BLACK,  curses.COLOR_CYAN)
    curses.init_pair(C_SELECTED, curses.COLOR_BLACK,  curses.COLOR_WHITE)
    curses.init_pair(C_EXCLUDED, curses.COLOR_RED,    -1)
    curses.init_pair(C_NORMAL,   curses.COLOR_WHITE,  -1)
    curses.init_pair(C_WARNING,  curses.COLOR_YELLOW, -1)
    curses.init_pair(C_SUCCESS,  curses.COLOR_GREEN,  -1)
    curses.init_pair(C_ERROR,    curses.COLOR_RED,    -1)
    curses.init_pair(C_DIM,      curses.COLOR_WHITE,  -1)
    curses.init_pair(C_MARKED,   curses.COLOR_GREEN,  -1)


def cp(pair_id: int) -> int:
    return curses.color_pair(pair_id)


def _safe(win, y: int, x: int, text: str, attr: int = 0) -> None:
    h, w = win.getmaxyx()
    if 0 <= y < h and 0 <= x < w:
        try:
            win.addstr(y, x, str(text)[:w - x - 1], attr)
        except curses.error:
            pass


def _draw_header(stdscr, subtitle: str = "") -> None:
    h, w = stdscr.getmaxyx()
    title = f" HMG Infosec Standard 5 – Disk Erasure Tool  v{VERSION} "
    try:
        stdscr.attron(cp(C_HEADER) | curses.A_BOLD)
        stdscr.addstr(0, 0, title.center(w - 1))
        stdscr.attroff(cp(C_HEADER) | curses.A_BOLD)
    except curses.error:
        pass
    if subtitle:
        _safe(stdscr, 1, 2, subtitle, cp(C_WARNING) | curses.A_BOLD)


def _draw_footer(stdscr, text: str) -> None:
    h, w = stdscr.getmaxyx()
    _safe(stdscr, h - 1, 0, text.ljust(w - 1), cp(C_DIM) | curses.A_REVERSE)


# ──────────────────────────────────────────────────────────────────────────────
# Pantalla 1 — Selección múltiple de discos
# ──────────────────────────────────────────────────────────────────────────────

def screen_disk_select(stdscr, disks: List[Disk],
                       caps: NwipeCaps) -> Optional[List[Disk]]:
    """
    Selección múltiple de discos.
    SPACE : marcar / desmarcar
    ENTER : confirmar selección (mínimo 1 disco)
    Q/ESC : salir
    """
    curses.curs_set(0)
    selectable = [d for d in disks if not d.is_excluded]
    excluded   = [d for d in disks if d.is_excluded]
    cursor     = 0
    marked: Set[str] = set()    # paths seleccionados

    while True:
        stdscr.clear()
        h, w = stdscr.getmaxyx()
        _draw_header(stdscr, "Selección de discos")

        _safe(stdscr, 2, 2, f"Motor: nwipe {caps.version}",
              cp(C_SUCCESS) | curses.A_BOLD)
        _safe(stdscr, 3, 2,
              "ADVERTENCIA: El borrado es IRREVERSIBLE. Verifique los discos marcados.",
              cp(C_WARNING))

        # Cabecera de columnas
        _safe(stdscr, 5, 2,
              f"     {'DISPOSITIVO':<12} {'TAMAÑO':>10}  {'TIPO':<12} {'BUS':<7} MODELO",
              cp(C_NORMAL) | curses.A_BOLD)
        _safe(stdscr, 6, 2, "-" * min(w - 4, 74), cp(C_DIM))

        row = 7
        for i, disk in enumerate(selectable):
            if row >= h - 5:
                break

            is_cur    = (i == cursor)
            is_marked = disk.path in marked
            check     = "[X]" if is_marked else "[ ]"
            arrow     = ">" if is_cur else " "

            # Color: cursor sobre marcado → cyan sobre verde (no disponible en básico)
            #         cursor solo          → inverso blanco
            #         marcado solo         → verde
            #         normal               → blanco
            if is_cur and is_marked:
                attr = cp(C_SELECTED) | curses.A_BOLD
            elif is_cur:
                attr = cp(C_SELECTED) | curses.A_BOLD
            elif is_marked:
                attr = cp(C_MARKED) | curses.A_BOLD
            else:
                attr = cp(C_NORMAL)

            check_attr = cp(C_SUCCESS) | curses.A_BOLD if is_marked else cp(C_DIM)
            line_attr  = attr

            # Dibujamos check y línea por separado para colores distintos
            _safe(stdscr, row, 2,  f"{arrow} ", line_attr)
            _safe(stdscr, row, 4,  check, check_attr)
            _safe(stdscr, row, 8,
                  f"{disk.path:<12} {disk.size_str:>10}  "
                  f"{disk.disk_type:<12} {disk.transport:<7} {disk.model[:28]}",
                  line_attr)
            row += 1

        # Discos excluidos
        if excluded and row < h - 4:
            row += 1
            _safe(stdscr, row, 2,
                  "--- Excluidos (no disponibles) " + "-" * 22, cp(C_DIM))
            row += 1
            for disk in excluded:
                if row >= h - 3:
                    break
                _safe(stdscr, row, 2,
                      f"    {disk.path:<12} {disk.size_str:>10}  "
                      f"{disk.disk_type:<12} {disk.transport:<7} "
                      f"{disk.model[:18]}  [{disk.exclusion_reason}]",
                      cp(C_EXCLUDED) | curses.A_DIM)
                row += 1

        # Estado de selección
        n = len(marked)
        if n > 0:
            sel_info = f"Marcados: {n} disco(s)   →   ENTER para continuar"
            sel_attr = cp(C_SUCCESS) | curses.A_BOLD
        else:
            sel_info = "Ningún disco marcado   (SPACE para marcar)"
            sel_attr = cp(C_DIM)
        _safe(stdscr, h - 3, 2, sel_info, sel_attr)

        _draw_footer(stdscr,
                     " SPACE: marcar/desmarcar   ↑↓: navegar   ENTER: continuar   Q: salir ")
        stdscr.refresh()

        key = stdscr.getch()

        if key == curses.KEY_UP:
            cursor = max(0, cursor - 1)
        elif key == curses.KEY_DOWN:
            cursor = min(len(selectable) - 1, cursor + 1)
        elif key == ord(" ") and selectable:
            path = selectable[cursor].path
            if path in marked:
                marked.discard(path)
            else:
                marked.add(path)
        elif key in (curses.KEY_ENTER, ord("\n"), ord("\r")):
            if marked:
                return [d for d in selectable if d.path in marked]
        elif key in (ord("q"), ord("Q"), 27):
            return None


# ──────────────────────────────────────────────────────────────────────────────
# Pantalla 2 — Selección de estándar
# ──────────────────────────────────────────────────────────────────────────────

def screen_standard_select(stdscr, disks: List[Disk],
                            caps: NwipeCaps) -> Optional[str]:
    """
    Devuelve "baseline", "enhanced", None (volver) o "quit".
    Si enhanced no está soportado por nwipe, se muestra con aviso.
    """
    has_ssd = any(d.disk_type in ("SSD", "NVMe SSD") for d in disks)

    options = [
        ("baseline",
         "IS5 Baseline",
         "1 pasada de datos aleatorios",
         f"nwipe --method=random   |   Clasificación: OFFICIAL",
         True),
        ("enhanced",
         "IS5 Enhanced",
         "3 pasadas: 0x00 → 0xFF → aleatorio",
         f"nwipe --method=is5enh   |   Para clasificaciones superiores",
         caps.has_is5enh),
    ]
    cursor = 0

    while True:
        stdscr.clear()
        h, w = stdscr.getmaxyx()
        _draw_header(stdscr, "Selección de estándar")

        # Lista de discos seleccionados
        _safe(stdscr, 3, 2, f"Discos seleccionados ({len(disks)}):",
              cp(C_NORMAL) | curses.A_BOLD)
        for i, disk in enumerate(disks):
            _safe(stdscr, 4 + i, 4,
                  f"• {disk.path}  {disk.size_str}  {disk.model}  [{disk.disk_type}]",
                  cp(C_NORMAL))

        base_row = 4 + len(disks) + 1

        if has_ssd:
            _safe(stdscr, base_row, 2,
                  "AVISO SSD: wear-leveling puede limitar la eficacia del borrado software.",
                  cp(C_WARNING))
            _safe(stdscr, base_row + 1, 2,
                  "Para máxima seguridad: ATA Secure Erase o destrucción física.",
                  cp(C_WARNING))
            base_row += 3

        _safe(stdscr, base_row, 2, "Seleccione el estándar:",
              cp(C_NORMAL) | curses.A_BOLD)
        base_row += 2

        for i, (key, name, short, detail, available) in enumerate(options):
            is_cur = (i == cursor)
            mark   = "(*)" if is_cur else "( )"

            if not available:
                attr = cp(C_DIM)
                note = "  [nwipe no soporta is5enh — actualice nwipe]"
            elif is_cur:
                attr = cp(C_SELECTED) | curses.A_BOLD
                note = ""
            else:
                attr = cp(C_NORMAL)
                note = ""

            _safe(stdscr, base_row,     4, f"{mark} {name} — {short}{note}", attr)
            _safe(stdscr, base_row + 1, 8, detail, cp(C_DIM))
            base_row += 3

        _draw_footer(stdscr,
                     " ↑↓: navegar   ENTER: confirmar   B: volver   Q: salir ")
        stdscr.refresh()

        key = stdscr.getch()
        if key == curses.KEY_UP:
            cursor = max(0, cursor - 1)
        elif key == curses.KEY_DOWN:
            cursor = min(len(options) - 1, cursor + 1)
        elif key in (curses.KEY_ENTER, ord("\n"), ord("\r")):
            std_key, _, _, _, available = options[cursor]
            if not available:
                # Mostrar error brevemente y no avanzar
                _safe(stdscr, h - 3, 2,
                      "Este método no está disponible en la versión instalada de nwipe.",
                      cp(C_ERROR) | curses.A_BOLD)
                stdscr.refresh()
                time.sleep(2)
            else:
                return std_key
        elif key in (ord("b"), ord("B")):
            return None
        elif key in (ord("q"), ord("Q"), 27):
            return "quit"


# ──────────────────────────────────────────────────────────────────────────────
# Pantalla 3 — Confirmación
# ──────────────────────────────────────────────────────────────────────────────

def screen_confirm(stdscr, disks: List[Disk], standard: str,
                   caps: NwipeCaps) -> bool:
    """
    El usuario debe escribir "CONFIRMAR" (en mayúsculas) para proceder.
    """
    method = NWIPE_METHODS[standard]

    stdscr.clear()
    h, w = stdscr.getmaxyx()
    _draw_header(stdscr, "Confirmación requerida")

    _safe(stdscr, 3, 2,
          "!!! ÚLTIMA ADVERTENCIA — ESTA OPERACIÓN ES COMPLETAMENTE IRREVERSIBLE !!!",
          cp(C_ERROR) | curses.A_BOLD)

    _safe(stdscr, 5, 2, f"Estándar : {STANDARD_LABELS[standard]}", cp(C_NORMAL))
    _safe(stdscr, 6, 2, f"Comando  : nwipe --method={method}", cp(C_NORMAL))
    _safe(stdscr, 7, 2, f"Discos a borrar ({len(disks)}):",
          cp(C_NORMAL) | curses.A_BOLD)

    for i, disk in enumerate(disks):
        _safe(stdscr, 8 + i, 4,
              f"• {disk.path:<12} {disk.size_str:>10}  "
              f"{disk.model}  [{disk.disk_type}]",
              cp(C_ERROR) | curses.A_BOLD)

    prompt_row = 8 + len(disks) + 1
    _safe(stdscr, prompt_row, 2,
          'Para confirmar, escriba "CONFIRMAR" y pulse ENTER:',
          cp(C_WARNING) | curses.A_BOLD)
    _safe(stdscr, prompt_row + 1, 2,
          "Escriba cualquier otra cosa o pulse ESC para cancelar.",
          cp(C_DIM))
    _safe(stdscr, prompt_row + 3, 2, "> ", cp(C_NORMAL) | curses.A_BOLD)
    stdscr.refresh()

    curses.echo()
    curses.curs_set(1)
    try:
        raw        = stdscr.getstr(prompt_row + 3, 4, 30)
        user_input = raw.decode("utf-8", errors="ignore").strip()
    except Exception:
        user_input = ""
    finally:
        curses.noecho()
        curses.curs_set(0)

    return user_input == "CONFIRMAR"


# ──────────────────────────────────────────────────────────────────────────────
# Pantalla 4 — Resultado y certificado
# ──────────────────────────────────────────────────────────────────────────────

def _save_certificate(result: EraseResult) -> None:
    duration = (result.end_time - result.start_time).total_seconds()
    try:
        with open(result.log_path, "a") as f:
            sep = "=" * 62
            f.write(f"\n{sep}\n")
            f.write("CERTIFICADO DE BORRADO — HMG INFOSEC STANDARD 5\n")
            f.write(f"{sep}\n")
            f.write(f"Herramienta  : HMG IS5 Erasure Tool v{VERSION}\n")
            f.write(f"Motor        : nwipe\n")
            f.write(f"Estándar     : {STANDARD_LABELS[result.standard]}\n")
            f.write(f"Inicio       : {result.start_time.isoformat()}\n")
            f.write(f"Fin          : {result.end_time.isoformat()}\n")
            f.write(f"Duración     : {format_duration(duration)}\n")
            f.write(f"Resultado    : {'ÉXITO' if result.success else 'FALLO'}\n")
            if result.error:
                f.write(f"Error        : {result.error}\n")
            f.write(f"\nDiscos borrados ({len(result.disks)}):\n")
            for disk in result.disks:
                f.write(
                    f"  • {disk.path:<14} {disk.size_str:>10}  "
                    f"{disk.disk_type:<12} {disk.model}\n"
                )
            f.write(f"{sep}\n")
    except Exception as e:
        logging.warning(f"No se pudo guardar el certificado: {e}")


def screen_result(stdscr, result: EraseResult) -> bool:
    """
    Muestra el resultado, guarda el certificado.
    Devuelve True si el usuario quiere borrar otro lote.
    """
    _save_certificate(result)
    stdscr.clear()
    h, w = stdscr.getmaxyx()
    _draw_header(stdscr, "Resultado del borrado")

    row = 3
    if result.success:
        _safe(stdscr, row, 2, "BORRADO COMPLETADO CON ÉXITO",
              cp(C_SUCCESS) | curses.A_BOLD)
    else:
        _safe(stdscr, row, 2, "BORRADO FALLIDO O INTERRUMPIDO",
              cp(C_ERROR) | curses.A_BOLD)
    row += 2

    duration = (result.end_time - result.start_time).total_seconds()
    _safe(stdscr, row, 2,
          f"Estándar  : {STANDARD_LABELS[result.standard]}", cp(C_NORMAL))
    row += 1
    _safe(stdscr, row, 2,
          f"Inicio    : {result.start_time.strftime('%Y-%m-%d %H:%M:%S')}",
          cp(C_NORMAL))
    row += 1
    _safe(stdscr, row, 2,
          f"Fin       : {result.end_time.strftime('%Y-%m-%d %H:%M:%S')}",
          cp(C_NORMAL))
    row += 1
    _safe(stdscr, row, 2, f"Duración  : {format_duration(duration)}", cp(C_NORMAL))
    row += 2

    if result.error:
        _safe(stdscr, row, 2, f"Error     : {result.error}", cp(C_ERROR))
        row += 2

    _safe(stdscr, row, 2, f"Discos borrados ({len(result.disks)}):",
          cp(C_NORMAL) | curses.A_BOLD)
    row += 1
    for disk in result.disks:
        icon = "OK " if result.success else "?? "
        _safe(stdscr, row, 4,
              f"{icon} {disk.path:<12} {disk.size_str:>10}  "
              f"{disk.disk_type:<12} {disk.model[:28]}",
              cp(C_SUCCESS) if result.success else cp(C_WARNING))
        row += 1

    row += 1
    _safe(stdscr, row, 2, f"Log/certificado: {result.log_path}", cp(C_DIM))
    row += 2
    _safe(stdscr, row, 2, "¿Borrar otro lote de discos? (s/n): ",
          cp(C_NORMAL) | curses.A_BOLD)
    stdscr.refresh()

    curses.echo()
    try:
        ans = stdscr.getstr(row, 37, 1).decode("utf-8", errors="ignore").strip().lower()
    except Exception:
        ans = "n"
    curses.noecho()

    return ans in ("s", "y")


# ──────────────────────────────────────────────────────────────────────────────
# Flujo principal
# ──────────────────────────────────────────────────────────────────────────────

# Dict mutable para pasar estado entre llamadas a curses.wrapper()
_state: dict = {}


def _selection_ui(stdscr) -> None:
    """
    Fase 1 (dentro de curses): selección de discos, estándar y confirmación.
    Guarda (disks, standard) en _state["selection"] o None si el usuario cancela.
    """
    curses.cbreak()
    stdscr.keypad(True)
    _init_colors()
    caps: NwipeCaps = _state["caps"]

    while True:
        # Paso 1: selección de discos (multi-select)
        disks = get_disks()
        selected = screen_disk_select(stdscr, disks, caps)
        if selected is None:
            _state["selection"] = None
            return

        # Paso 2: selección de estándar
        standard = screen_standard_select(stdscr, selected, caps)
        if standard == "quit":
            _state["selection"] = None
            return
        if standard is None:
            continue   # volver a selección de discos

        # Paso 3: confirmación
        if not screen_confirm(stdscr, selected, standard, caps):
            stdscr.clear()
            _safe(stdscr, 5, 5, "Operación cancelada. Pulse cualquier tecla.",
                  cp(C_WARNING) | curses.A_BOLD)
            stdscr.refresh()
            stdscr.getch()
            continue   # volver a selección de discos

        _state["selection"] = (selected, standard)
        return


def _result_ui(stdscr) -> None:
    """Fase 3 (dentro de curses): muestra el resultado."""
    curses.cbreak()
    stdscr.keypad(True)
    _init_colors()
    _state["another"] = screen_result(stdscr, _state["result"])


def main() -> None:
    check_root()
    log_path = get_log_path()
    setup_logging(log_path)

    caps = require_nwipe()   # aborta si nwipe no está instalado
    _state["caps"] = caps

    if not caps.has_is5enh:
        logging.warning(
            "nwipe instalado no soporta --method=is5enh. "
            "IS5 Enhanced no estará disponible. Actualice nwipe."
        )

    while True:
        # ── Fase 1: Selección (curses) ────────────────────────────────────────
        curses.wrapper(_selection_ui)
        selection = _state.get("selection")
        if selection is None:
            break

        disks, standard = selection
        method = NWIPE_METHODS[standard]
        logging.info(
            f"Confirmado: {[d.path for d in disks]}  "
            f"estándar={standard}  método=nwipe --method={method}"
        )

        # ── Fase 2: Borrado con nwipe (fuera de curses) ───────────────────────
        start_time = datetime.now()
        success, error = run_nwipe(disks, standard, caps, log_path)
        end_time = datetime.now()

        logging.info(
            f"Borrado finalizado: éxito={success}  "
            f"duración={format_duration((end_time - start_time).total_seconds())}"
        )

        # ── Fase 3: Resultado (curses) ────────────────────────────────────────
        _state["result"] = EraseResult(
            disks=disks, standard=standard,
            start_time=start_time, end_time=end_time,
            success=success, log_path=log_path, error=error,
        )
        curses.wrapper(_result_ui)

        if not _state.get("another", False):
            break

    print(f"\nSesión finalizada. Log/certificado en: {log_path}\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrumpido por el usuario.")
        sys.exit(0)
    except Exception as e:
        print(f"Error fatal: {e}")
        logging.exception("Error fatal")
        sys.exit(1)
