"""
discord_rpc.py — Discord Rich Presence for IDA Pro 9.x
=======================================================
Install:  pip install pypresence
Place in: %APPDATA%\\Hex-Rays\\IDA Pro\\plugins\\  (Windows)
          ~/.idapro/plugins/                        (macOS/Linux)

Hotkeys:  Ctrl+Shift+A  -- toggle anonymizer
          Ctrl+Shift+N  -- toggle shadow mode (ntdll overlay)
          Edit > Plugins > Discord RPC  -- settings dialog

Discord Developer Portal: https://discord.com/developers/applications
  Create app -> App ID -> paste into CONFIG["app_id"]
  Rich Presence -> Art Assets -> upload logo as "ida_logo"
"""

import os
import random
import threading
import time

import ida_funcs
import ida_ida
import ida_idaapi
import ida_kernwin
import ida_loader
import ida_name
import ida_nalt
import ida_segment
import idaapi
import idautils
import idc

try:
    from pypresence import Presence
    HAS_PYPRESENCE = True
except ImportError:
    HAS_PYPRESENCE = False

# =============================================================================
# Configuration
# =============================================================================

VERSION = "1.0.0"

CONFIG = {
    "enabled":               True,
    "app_id":                "1467007916547510457",
    "large_image":           "ida_logo",
    "large_text":            "IDA Pro 9.x",

    "anonymize":             True,
    "shadow_mode":           True,
    "show_arch":             True,
    "show_segment":          True,
    "show_view":             True,
    "show_func_count":       True,
    "show_progress_bar":     True,
    "show_func_size":        True,
    "show_xrefs":            True,
    "show_time_on_func":     True,

    "afk_threshold_s":       300,
    "func_count_interval_s": 15.0,
    "xref_cache_interval_s": 10.0,
}

RECONNECT_INTERVAL_MS = 15_000
MIN_UPDATE_INTERVAL_S  = 5.0

# =============================================================================
# Constants
# =============================================================================

_ANON_ALIASES = [
    "mystery.bin",   "classified.exe", "redacted.dll",
    "unknown.sys",   "secret.bin",     "target.exe",
    "sample.dll",    "payload.bin",    "artifact.exe",
    "project_x.dll",
]

_MATRIX_CHARS = "0123456789ABCDEFabcdef!@#$%^&*?<>[]{}|~+-=/"

_NT_FUNCTIONS = [
    ("NtCreateFile",                     0x14,  1243),
    ("NtOpenFile",                       0x14,   892),
    ("NtReadFile",                       0x14,   734),
    ("NtWriteFile",                      0x14,   456),
    ("NtClose",                          0x14,  4821),
    ("NtReadVirtualMemory",              0x14,   847),
    ("NtWriteVirtualMemory",             0x14,   312),
    ("NtQueryVirtualMemory",             0x14,   589),
    ("NtProtectVirtualMemory",           0x14,   734),
    ("NtAllocateVirtualMemory",          0x14,   921),
    ("NtFreeVirtualMemory",              0x14,   445),
    ("NtOpenProcess",                    0x14,   623),
    ("NtCreateThread",                   0x14,   287),
    ("NtSuspendThread",                  0x14,   156),
    ("NtResumeThread",                   0x14,   203),
    ("NtGetContextThread",               0x14,   178),
    ("NtSetContextThread",               0x14,   134),
    ("NtQuerySystemInformation",         0x14,   891),
    ("NtQueryInformationProcess",        0x14,  1102),
    ("NtSetInformationProcess",          0x14,   347),
    ("NtQueryInformationThread",         0x14,   512),
    ("NtMapViewOfSection",               0x14,   512),
    ("NtUnmapViewOfSection",             0x14,   289),
    ("NtCreateSection",                  0x14,   234),
    ("NtDuplicateObject",                0x14,   445),
    ("NtDelayExecution",                 0x14,   567),
    ("NtLoadDriver",                     0x14,    12),
    ("NtUnloadDriver",                   0x14,     8),
    ("NtCreateMutant",                   0x14,    89),
    ("NtCreateEvent",                    0x14,   345),
    ("NtSetEvent",                       0x14,   678),
    ("NtTerminateProcess",               0x14,   234),
    ("NtTerminateThread",                0x14,   189),
    ("LdrLoadDll",                      0x180,   892),
    ("LdrUnloadDll",                     0xC0,   234),
    ("LdrGetProcedureAddress",          0x110,  1567),
    ("LdrFindEntryForAddress",           0x90,   445),
    ("LdrInitializeThunk",              0x200,    12),
    ("LdrpLoadDll",                     0x340,    67),
    ("LdrpFindLoadedDllByName",         0x1A0,   234),
    ("LdrpHandleInvalidUserCallTarget",  0xC0,    34),
    ("RtlAllocateHeap",                  0x80,  3421),
    ("RtlFreeHeap",                      0x70,  2891),
    ("RtlReAllocateHeap",                0xA0,   567),
    ("RtlCreateHeap",                   0x160,    45),
    ("RtlAddVectoredExceptionHandler",   0x60,   234),
    ("RtlRemoveVectoredExceptionHandler",0x50,    89),
    ("RtlCaptureStackBackTrace",         0x50,  1234),
    ("RtlLookupFunctionEntry",           0xB0,   892),
    ("RtlVirtualUnwind",                0x1A0,   345),
    ("RtlInitializeCriticalSection",     0x40,  2341),
    ("RtlEnterCriticalSection",          0x30,  4521),
    ("RtlLeaveCriticalSection",          0x30,  4498),
    ("RtlHashUnicodeString",             0x60,   234),
    ("RtlDecompressBuffer",              0x90,   123),
    ("RtlCompressBuffer",                0x80,    67),
    ("RtlImageNtHeader",                 0x30,  1892),
    ("RtlImageDirectoryEntryToData",     0x70,   934),
    ("RtlGetVersion",                    0x60,   445),
    ("RtlRandomEx",                      0x40,   234),
]

_primary_instance: "DiscordRPCPlugin | None" = None
_primary_lock = threading.Lock()

# =============================================================================
# Logging
# =============================================================================

def log(msg: str) -> None:
    try:
        ida_kernwin.msg(f"[Discord] {msg}\n")
    except BaseException:
        pass

# =============================================================================
# Helpers
# =============================================================================

def _matrix_string(length: int = 8) -> str:
    return "".join(random.choices(_MATRIX_CHARS, k=length))


def _get_arch() -> str:
    try:
        proc = ida_ida.inf_get_procname().lower()
        bits = 64 if ida_ida.inf_is_64bit() else 32
        if "metapc" in proc or "pc" in proc:
            return "x64" if bits == 64 else "x86"
        if "arm" in proc:
            return "ARM64" if bits == 64 else "ARM"
        if "mips" in proc:
            return f"MIPS{bits}"
        if "ppc" in proc or "powerpc" in proc:
            return f"PPC{bits}"
        return f"{ida_ida.inf_get_procname().upper()}{bits}"
    except BaseException:
        return ""


def _get_segment(ea: int) -> str:
    try:
        seg = ida_segment.getseg(ea)
        return ida_segment.get_segm_name(seg) if seg else ""
    except BaseException:
        return ""


def _get_active_view() -> str:
    try:
        widget = ida_kernwin.get_current_widget()
        if widget is None:
            return ""
        title = ida_kernwin.get_widget_title(widget) or ""
        if "Pseudocode" in title:
            return "Pseudocode"
        if "IDA View" in title or "Disassembly" in title:
            return "Disasm"
        return ""
    except BaseException:
        return ""


def _get_func_stats() -> tuple[int, int]:
    try:
        total = named = 0
        for ea in idautils.Functions():
            total += 1
            n = idc.get_func_name(ea) or ""
            if n and not n.startswith(("sub_", "j_", "nullsub_", "unknown_")):
                named += 1
        return named, total
    except BaseException:
        return 0, 0


def _get_xref_count(func_ea: int) -> int:
    try:
        return len(list(idautils.CodeRefsTo(func_ea, True)))
    except BaseException:
        return 0


def _progress_bar(named: int, total: int, width: int = 6) -> str:
    if total == 0:
        return ""
    pct    = named / total
    filled = int(pct * width)
    bar    = "█" * filled + "░" * (width - filled)
    return f"[{bar}] {int(pct * 100)}%"


def _fmt_duration(seconds: float) -> str:
    s = int(seconds)
    if s < 60:
        return f"{s}s"
    m, s = divmod(s, 60)
    if m < 60:
        return f"{m}m {s}s"
    h, m = divmod(m, 60)
    return f"{h}h {m}m"


# =============================================================================
# Hotkeys
# =============================================================================

class _ToggleAnonAction(ida_kernwin.action_handler_t):
    NAME  = "discord_rpc:toggle_anon"
    LABEL = "Discord RPC: Toggle Anonymizer"
    HOT   = "Ctrl+Shift+A"

    def __init__(self, plugin: "DiscordRPCPlugin"):
        ida_kernwin.action_handler_t.__init__(self)
        self.plugin = plugin

    def activate(self, ctx) -> int:
        try:
            CONFIG["anonymize"] = not CONFIG["anonymize"]
            log(f"Anonymizer {'ON' if CONFIG['anonymize'] else 'OFF'}")
            self.plugin.last_func = ""
            self.plugin.update_presence(force=True)
        except BaseException:
            pass
        return 1

    def update(self, ctx) -> int:
        return ida_kernwin.AST_ENABLE_ALWAYS


class _ToggleShadowAction(ida_kernwin.action_handler_t):
    NAME  = "discord_rpc:toggle_shadow"
    LABEL = "Discord RPC: Toggle Shadow Mode"
    HOT   = "Ctrl+Shift+N"

    def __init__(self, plugin: "DiscordRPCPlugin"):
        ida_kernwin.action_handler_t.__init__(self)
        self.plugin = plugin

    def activate(self, ctx) -> int:
        try:
            CONFIG["shadow_mode"] = not CONFIG["shadow_mode"]
            log(f"Shadow Mode {'ON' if CONFIG['shadow_mode'] else 'OFF'}")
            self.plugin.last_func = ""
            self.plugin.update_presence(force=True)
        except BaseException:
            pass
        return 1

    def update(self, ctx) -> int:
        return ida_kernwin.AST_ENABLE_ALWAYS


# =============================================================================
# Settings dialog
# =============================================================================

def _show_config_dialog(plugin: "DiscordRPCPlugin") -> None:
    try:
        try:
            from PyQt5 import QtWidgets, QtCore
        except ImportError:
            from PySide6 import QtWidgets, QtCore

        class SettingsDialog(QtWidgets.QDialog):
            def __init__(self):
                super().__init__()
                self.setWindowTitle(f"Discord RPC  v{VERSION}")
                self.setWindowFlags(
                    self.windowFlags() & ~QtCore.Qt.WindowContextHelpButtonHint
                )
                self.setMinimumWidth(420)
                self._plugin = plugin
                self._build_ui()

            def _build_ui(self):
                root = QtWidgets.QVBoxLayout(self)
                root.setSpacing(10)
                root.setContentsMargins(14, 12, 14, 12)

                status_row = QtWidgets.QHBoxLayout()
                status_txt = "Connected" if plugin.running else "Disconnected"
                self._status_lbl = QtWidgets.QLabel(f"<b>{status_txt}</b>")
                status_row.addWidget(self._status_lbl)
                status_row.addStretch()

                if not plugin.running:
                    btn_reconnect = QtWidgets.QPushButton("Reconnect")
                    btn_reconnect.setFixedWidth(90)
                    btn_reconnect.clicked.connect(self._on_reconnect)
                    status_row.addWidget(btn_reconnect)

                root.addLayout(status_row)

                if plugin.running and plugin.current_file:
                    fname = plugin._tracking_func or "—"
                    root.addWidget(QtWidgets.QLabel(
                        f"<small><font color='gray'>"
                        f"  {plugin.current_file}  ·  {fname}"
                        f"</font></small>"
                    ))

                sep0 = QtWidgets.QFrame()
                sep0.setFrameShape(QtWidgets.QFrame.HLine)
                sep0.setFrameShadow(QtWidgets.QFrame.Sunken)
                root.addWidget(sep0)

                self._checks: dict[str, QtWidgets.QCheckBox] = {}

                grp_env = QtWidgets.QGroupBox("Environment")
                lay_env = QtWidgets.QVBoxLayout(grp_env)
                lay_env.setSpacing(4)
                for key, label in [
                    ("show_arch",    "Architecture  (x64 / x86 / ARM)"),
                    ("show_segment", "Segment  (.text / .data / .rdata)"),
                    ("show_view",    "Active view  (Disasm / Pseudocode)"),
                ]:
                    chk = QtWidgets.QCheckBox(label)
                    chk.setChecked(CONFIG[key])
                    lay_env.addWidget(chk)
                    self._checks[key] = chk
                root.addWidget(grp_env)

                grp_fn = QtWidgets.QGroupBox("Function")
                lay_fn = QtWidgets.QVBoxLayout(grp_fn)
                lay_fn.setSpacing(4)

                self._chk_bar   = QtWidgets.QCheckBox("Progress bar  [████░░] 67%")
                self._chk_count = QtWidgets.QCheckBox("Function counter  (X / Y named)")
                self._chk_bar.setChecked(CONFIG["show_progress_bar"])
                self._chk_count.setChecked(CONFIG["show_func_count"])
                self._chk_count.setEnabled(not CONFIG["show_progress_bar"])
                self._chk_bar.toggled.connect(
                    lambda on: self._chk_count.setEnabled(not on)
                )
                lay_fn.addWidget(self._chk_bar)
                count_row = QtWidgets.QHBoxLayout()
                count_row.addSpacing(20)
                count_row.addWidget(self._chk_count)
                lay_fn.addLayout(count_row)
                self._checks["show_progress_bar"] = self._chk_bar
                self._checks["show_func_count"]   = self._chk_count
                lay_fn.addSpacing(2)

                for key, label in [
                    ("show_func_size",    "Function size  (0x2A0 bytes)"),
                    ("show_xrefs",        "Caller count  (↑12 xrefs)"),
                    ("show_time_on_func", "Time on function  (4m 32s)"),
                ]:
                    chk = QtWidgets.QCheckBox(label)
                    chk.setChecked(CONFIG[key])
                    lay_fn.addWidget(chk)
                    self._checks[key] = chk
                root.addWidget(grp_fn)

                grp_priv = QtWidgets.QGroupBox("Privacy & Style")
                lay_priv = QtWidgets.QVBoxLayout(grp_priv)
                lay_priv.setSpacing(6)

                chk_anon = QtWidgets.QCheckBox(
                    "Anonymize  — hide file & function names  [Ctrl+Shift+A]"
                )
                chk_anon.setChecked(CONFIG["anonymize"])
                lay_priv.addWidget(chk_anon)
                self._checks["anonymize"] = chk_anon

                sep_priv = QtWidgets.QFrame()
                sep_priv.setFrameShape(QtWidgets.QFrame.HLine)
                sep_priv.setFrameShadow(QtWidgets.QFrame.Sunken)
                lay_priv.addWidget(sep_priv)

                chk_shadow = QtWidgets.QCheckBox(
                    "Shadow Mode  — always shows ntdll.dll internals  [Ctrl+Shift+N]"
                )
                chk_shadow.setChecked(CONFIG["shadow_mode"])
                lay_priv.addWidget(chk_shadow)
                self._checks["shadow_mode"] = chk_shadow
                lay_priv.addWidget(QtWidgets.QLabel(
                    "<small><font color='gray'>"
                    "  Overrides all display settings. "
                    "Rotates to a random NT function every 2–5 min."
                    "</font></small>"
                ))
                root.addWidget(grp_priv)

                sep1 = QtWidgets.QFrame()
                sep1.setFrameShape(QtWidgets.QFrame.HLine)
                sep1.setFrameShadow(QtWidgets.QFrame.Sunken)
                root.addWidget(sep1)

                btn_row = QtWidgets.QHBoxLayout()
                btn_row.addStretch()
                btn_apply  = QtWidgets.QPushButton("Apply")
                btn_ok     = QtWidgets.QPushButton("OK")
                btn_cancel = QtWidgets.QPushButton("Cancel")
                for b in (btn_apply, btn_ok, btn_cancel):
                    b.setFixedWidth(70)
                btn_ok.setDefault(True)
                btn_apply.clicked.connect(self._apply)
                btn_ok.clicked.connect(self._ok)
                btn_cancel.clicked.connect(self.reject)
                btn_row.addWidget(btn_apply)
                btn_row.addWidget(btn_ok)
                btn_row.addWidget(btn_cancel)
                root.addLayout(btn_row)

            def _apply(self):
                for k, chk in self._checks.items():
                    CONFIG[k] = chk.isChecked()
                self._plugin.last_func = ""
                self._plugin.update_presence(force=True)

            def _ok(self):
                self._apply()
                self.accept()

            def _on_reconnect(self):
                self._plugin._try_connect()
                if self._plugin.running:
                    self._plugin.update_presence(force=True)
                status_txt = "Connected" if self._plugin.running else "Disconnected"
                self._status_lbl.setText(f"<b>{status_txt}</b>")

        dlg = SettingsDialog()
        # PySide6 deprecated exec_() in favour of exec(); fall back for PyQt5
        (dlg.exec if hasattr(dlg, "exec") else dlg.exec_)()

    except BaseException as e:
        log(f"Settings dialog error: {e}")


# =============================================================================
# IDA Hooks
# =============================================================================

class IDAHooks(ida_kernwin.UI_Hooks):
    def __init__(self, plugin: "DiscordRPCPlugin"):
        ida_kernwin.UI_Hooks.__init__(self)
        self.plugin = plugin

    def ready_to_run(self) -> None:
        try:
            self.plugin._initial_timer_pending = False
            self.plugin.update_presence(force=True)
        except BaseException:
            pass

    def screen_ea_changed(self, ea: int, prev_ea: int) -> int:
        try:
            was_afk = self.plugin._is_afk
            self.plugin._last_movement = time.time()
            self.plugin._is_afk        = False
            if CONFIG["shadow_mode"]:
                if was_afk:
                    self.plugin.last_func = ""
                    self.plugin.update_presence(force=True)
            else:
                self.plugin.update_presence()
        except BaseException:
            pass
        return 0

    def current_widget_changed(self, widget, prev_widget) -> int:
        try:
            self.plugin._current_view = _get_active_view()
            if not CONFIG["shadow_mode"]:
                self.plugin.last_func = ""
                self.plugin.update_presence(force=True)
        except BaseException:
            pass
        return 0

    def preprocess_action(self, name: str) -> int:
        try:
            if not CONFIG["shadow_mode"]:
                if "GenPseudocode" in name or name == "hx:F5":
                    self.plugin._on_decompile_start()
        except BaseException:
            pass
        return 0


class IDBHooks(idaapi.IDB_Hooks):
    def __init__(self, plugin: "DiscordRPCPlugin"):
        idaapi.IDB_Hooks.__init__(self)
        self.plugin = plugin

    def database_inited(self, is_new_database: int, idc_script: str) -> int:
        try:
            p = self.plugin
            p.last_func          = ""
            p.current_file       = ""
            p._cached_arch       = ""
            p._cached_named      = 0
            p._cached_total      = 0
            p._last_count_time   = 0.0
            p._anon_alias        = random.choice(_ANON_ALIASES)
            p._func_since        = time.time()
            p._tracking_func     = ""
            p._cached_xrefs      = 0
            p._last_xref_time    = 0.0
            p._last_xref_ea      = idc.BADADDR
            if not p._initial_timer_pending:
                p._initial_timer_pending = True
                ida_kernwin.register_timer(1000, p._initial_update)
        except BaseException:
            pass
        return 0

    def closebase(self) -> int:
        try:
            self.plugin._clear_presence()
        except BaseException:
            pass
        return 0


# =============================================================================
# Plugin
# =============================================================================

class DiscordRPCPlugin(ida_idaapi.plugin_t):
    flags         = ida_idaapi.PLUGIN_FIX
    comment       = "Discord Rich Presence Integration"
    help          = "Shows current IDA session in Discord. Edit > Plugins > Discord RPC for settings."
    wanted_name   = "Discord RPC"
    wanted_hotkey = ""

    def __init__(self):
        try:
            super().__init__()
        except BaseException:
            pass

        self.rpc                    = None
        self.running                = False
        self.is_primary             = False
        self.active                 = False
        self.start_time             = int(time.time())

        self.hook                   = None
        self.idb_hook               = None
        self._anon_action           = None
        self._shadow_action         = None

        self.last_func              = ""
        self.current_file           = ""
        self.last_update_time       = 0.0
        self._initial_timer_pending = False
        self._current_view          = ""

        self._cached_arch           = ""
        self._cached_named          = 0
        self._cached_total          = 0
        self._last_count_time       = 0.0

        self._cached_xrefs          = 0
        self._last_xref_time        = 0.0
        self._last_xref_ea          = idc.BADADDR

        self._tracking_func         = ""
        self._func_since            = time.time()

        self._anon_alias            = random.choice(_ANON_ALIASES)
        self._matrix_func           = _matrix_string()
        self._matrix_file           = _matrix_string()
        self._shadow_func           = random.choice(_NT_FUNCTIONS)

        self._last_movement         = time.time()
        self._is_afk                = False

        self._is_decompiling        = False
        self._decompiling_func      = ""
        self._decompile_flash_end   = 0.0

    # =========================================================================
    # Lifecycle
    # =========================================================================

    def init(self) -> int:
        global _primary_instance

        if not CONFIG["enabled"]:
            return ida_idaapi.PLUGIN_SKIP

        if not HAS_PYPRESENCE:
            log("pypresence not found — run: pip install pypresence")
            return ida_idaapi.PLUGIN_SKIP

        # IDA loads plugins twice on macOS; only the first instance becomes primary.
        with _primary_lock:
            if _primary_instance is None:
                _primary_instance = self
                self.is_primary   = True
            else:
                return ida_idaapi.PLUGIN_KEEP

        self.active = True

        try:
            self.hook = IDAHooks(self)
            self.hook.hook()
        except BaseException:
            self.hook = None

        try:
            self.idb_hook = IDBHooks(self)
            self.idb_hook.hook()
        except BaseException:
            self.idb_hook = None

        try:
            self._anon_action = _ToggleAnonAction(self)
            desc = ida_kernwin.action_desc_t(
                _ToggleAnonAction.NAME, _ToggleAnonAction.LABEL,
                self._anon_action, _ToggleAnonAction.HOT,
            )
            ida_kernwin.register_action(desc)
            ida_kernwin.attach_action_to_menu(
                "Edit/Plugins/", _ToggleAnonAction.NAME, ida_kernwin.SETMENU_APP
            )
        except BaseException:
            pass

        try:
            self._shadow_action = _ToggleShadowAction(self)
            desc = ida_kernwin.action_desc_t(
                _ToggleShadowAction.NAME, _ToggleShadowAction.LABEL,
                self._shadow_action, _ToggleShadowAction.HOT,
            )
            ida_kernwin.register_action(desc)
            ida_kernwin.attach_action_to_menu(
                "Edit/Plugins/", _ToggleShadowAction.NAME, ida_kernwin.SETMENU_APP
            )
        except BaseException:
            pass

        self._try_connect()

        self._initial_timer_pending = True
        ida_kernwin.register_timer(4000,                             self._initial_update)
        ida_kernwin.register_timer(RECONNECT_INTERVAL_MS,            self._heartbeat)
        ida_kernwin.register_timer(5500,                             self._matrix_tick)
        ida_kernwin.register_timer(10_000,                           self._time_tick)
        ida_kernwin.register_timer(random.randint(120_000, 300_000), self._shadow_tick)

        log(f"v{VERSION} loaded")
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg: int) -> None:
        if self.is_primary:
            _show_config_dialog(self)

    def term(self) -> None:
        global _primary_instance

        if hasattr(self, "active"):
            self.active = False

        try:
            ida_kernwin.unregister_action(_ToggleAnonAction.NAME)
        except BaseException:
            pass
        try:
            ida_kernwin.unregister_action(_ToggleShadowAction.NAME)
        except BaseException:
            pass

        # Keep hook objects alive — nullifying SWIG wrappers during shutdown
        # causes the GC to invoke C++ destructors at the wrong time.
        try:
            if getattr(self, "hook", None):
                self.hook.unhook()
        except BaseException:
            pass

        try:
            if getattr(self, "idb_hook", None):
                self.idb_hook.unhook()
        except BaseException:
            pass

        if getattr(self, "is_primary", False):
            rpc, self.rpc = self.rpc, None
            self.running  = False
            if rpc:
                try:
                    rpc.clear()
                except BaseException:
                    pass
                try:
                    rpc.close()
                except BaseException:
                    pass

            with _primary_lock:
                _primary_instance = None

    # =========================================================================
    # Connection
    # =========================================================================

    def _try_connect(self) -> None:
        if self.running:
            return

        old, self.rpc = self.rpc, None
        self.running  = False
        if old:
            try:
                old.close()
            except BaseException:
                pass

        try:
            rpc = Presence(CONFIG["app_id"])
            rpc.connect()
            self.rpc          = rpc
            self.running      = True
            self.start_time   = int(time.time())
            self.last_func    = ""
            self.current_file = ""
            log("Connected to Discord")
        except BaseException:
            self.rpc     = None
            self.running = False

    def _clear_presence(self) -> None:
        rpc = self.rpc
        if rpc:
            try:
                rpc.clear()
            except BaseException:
                pass

    def _mark_disconnected(self) -> None:
        rpc, self.rpc = self.rpc, None
        self.running  = False
        if rpc:
            try:
                rpc.close()
            except BaseException:
                pass

    # =========================================================================
    # Decompiling flash
    # =========================================================================

    def _on_decompile_start(self) -> None:
        self._is_decompiling      = True
        self._decompiling_func    = self._tracking_func
        self._decompile_flash_end = time.time() + 4.0
        self.last_func            = ""
        self.update_presence(force=True)

    def _check_decompile_end(self) -> bool:
        if self._is_decompiling:
            if time.time() >= self._decompile_flash_end:
                self._is_decompiling = False
                self.last_func       = ""
            else:
                return True
        return False

    # =========================================================================
    # Timers
    # =========================================================================

    def _initial_update(self) -> int:
        self._initial_timer_pending = False
        try:
            if self.active:
                self.update_presence(force=True)
        except BaseException:
            pass
        return -1  # one-shot

    def _matrix_tick(self) -> int:
        if not self.active:
            return -1
        try:
            if CONFIG["anonymize"] and not CONFIG["shadow_mode"] and not self._is_afk:
                self._matrix_func = _matrix_string()
                self._matrix_file = _matrix_string()
                self.last_func    = ""
                self.update_presence(force=True)
        except BaseException:
            pass
        return 5500

    def _shadow_tick(self) -> int:
        if not self.active:
            return -1
        try:
            if CONFIG["shadow_mode"] and not self._is_afk:
                self._shadow_func = random.choice(_NT_FUNCTIONS)
                self.last_func    = ""
                self.update_presence(force=True)
        except BaseException:
            pass
        return random.randint(120_000, 300_000)

    def _time_tick(self) -> int:
        if not self.active:
            return -1
        try:
            now     = time.time()
            idle_s  = now - self._last_movement
            was_afk = self._is_afk

            if idle_s >= CONFIG["afk_threshold_s"]:
                if not self._is_afk:
                    self._is_afk   = True
                    self.last_func = ""
                self.update_presence(force=True)
            else:
                if was_afk:
                    self._is_afk   = False
                    self.last_func = ""
                    self.update_presence(force=True)
                elif (CONFIG["show_time_on_func"] and self._tracking_func) \
                        or self._is_decompiling:
                    self.update_presence(force=True)

        except BaseException:
            pass
        return 10_000

    def _heartbeat(self) -> int:
        if not self.active:
            return -1
        try:
            if not self.running:
                self._try_connect()
                if self.running:
                    self.update_presence(force=True)
        except BaseException:
            pass
        return RECONNECT_INTERVAL_MS

    # =========================================================================
    # Cache
    # =========================================================================

    def _refresh_metadata(self, force: bool = False) -> None:
        now = time.time()
        if force or not self._cached_arch:
            self._cached_arch = _get_arch()
        if CONFIG["show_func_count"] or CONFIG["show_progress_bar"]:
            if force or (now - self._last_count_time) >= CONFIG["func_count_interval_s"]:
                self._cached_named, self._cached_total = _get_func_stats()
                self._last_count_time = now

    def _refresh_xrefs(self, func_ea: int, force: bool = False) -> None:
        if not CONFIG["show_xrefs"] or func_ea == idc.BADADDR:
            return
        now = time.time()
        if force or func_ea != self._last_xref_ea \
                or (now - self._last_xref_time) >= CONFIG["xref_cache_interval_s"]:
            self._cached_xrefs   = _get_xref_count(func_ea)
            self._last_xref_time = now
            self._last_xref_ea   = func_ea

    # =========================================================================
    # Presence update
    # =========================================================================

    def update_presence(self, force: bool = False) -> None:
        if not self.is_primary or not self.active:
            return

        rpc = self.rpc
        if not self.running or rpc is None:
            return

        now = time.time()

        try:
            if CONFIG["shadow_mode"] and not self._is_afk:
                nt_name, nt_size, nt_xrefs = self._shadow_func
                key = f"__shadow_{nt_name}"
                if self.last_func != key or force:
                    self.last_func        = key
                    self.last_update_time = now
                    rpc.update(
                        details     = "ntdll.dll  (x64 · .text · Disasm)",
                        state       = f"{nt_name}  0x{nt_size:X}  ↑{nt_xrefs}",
                        large_image = CONFIG["large_image"],
                        large_text  = CONFIG["large_text"],
                        start       = self.start_time,
                    )
                return

            if self._is_afk:
                idle_str = _fmt_duration(now - self._last_movement)
                key      = f"__afk_{idle_str}"
                if self.last_func != key:
                    self.last_func        = key
                    self.last_update_time = now
                    rpc.update(
                        details     = "idle",
                        state       = f"away for {idle_str}",
                        large_image = CONFIG["large_image"],
                        large_text  = CONFIG["large_text"],
                        start       = self.start_time,
                    )
                return

            ea = ida_kernwin.get_screen_ea()
            if ea == idc.BADADDR:
                return

            try:
                root = ida_nalt.get_root_filename() \
                    or ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
            except BaseException:
                root = None

            if root:
                rname = os.path.basename(root)
                if rname.lower().endswith((".i64", ".idb")):
                    rname = os.path.splitext(rname)[0]
                rname = rname[:64]
            else:
                rname = "Unsaved"

            if rname != self.current_file:
                self.current_file   = rname
                self.last_func      = ""
                self._anon_alias    = random.choice(_ANON_ALIASES)
                self._func_since    = now
                self._tracking_func = ""
                force               = True
                self._refresh_metadata(force=True)

            if not force and (now - self.last_update_time) < MIN_UPDATE_INTERVAL_S:
                return

            self._refresh_metadata(force=force)

            try:
                func = ida_funcs.get_func(ea)
                if func:
                    raw   = idc.get_func_name(func.start_ea) or ""
                    fname = (ida_name.demangle_name(raw, ida_name.MNG_LONG_FORM)
                             or raw
                             or f"sub_{func.start_ea:X}")
                    fsize = func.end_ea - func.start_ea
                    fea   = func.start_ea
                else:
                    fname = f"0x{ea:X}"
                    fsize = 0
                    fea   = idc.BADADDR
            except BaseException:
                fname = f"0x{ea:X}"
                fsize = 0
                fea   = idc.BADADDR

            if fname != self._tracking_func:
                self._tracking_func = fname
                self._func_since    = now

            self._refresh_xrefs(fea, force=force)

            if self._check_decompile_end():
                flash_name = self._decompiling_func or fname
                if CONFIG["anonymize"]:
                    flash_name = f"sub_{self._matrix_func}"
                key = f"__decomp_{flash_name}"
                if self.last_func != key:
                    self.last_func        = key
                    self.last_update_time = now
                    rpc.update(
                        details     = "???.bin" if CONFIG["anonymize"] else rname,
                        state       = f"Decompiling {flash_name}...",
                        large_image = CONFIG["large_image"],
                        large_text  = CONFIG["large_text"],
                        start       = self.start_time,
                    )
                return

            if fname == self.last_func and not force:
                return

            self.last_func        = fname
            self.last_update_time = now

            display_file = f"{self._matrix_file}.bin" if CONFIG["anonymize"] else rname
            display_func = f"sub_{self._matrix_func}" if CONFIG["anonymize"] else fname

            arch = self._cached_arch  if CONFIG["show_arch"]    else ""
            seg  = _get_segment(ea)   if CONFIG["show_segment"] else ""
            view = self._current_view if CONFIG["show_view"]    else ""
            badges  = [b for b in (arch, seg, view) if b]
            details = (
                f"{display_file}  ({' · '.join(badges)})" if badges else display_file
            )

            parts = [display_func]

            if CONFIG["show_func_size"] and fsize > 0:
                parts.append(f"0x{fsize:X}")

            if CONFIG["show_xrefs"] and self._cached_xrefs > 0:
                parts.append(f"↑{self._cached_xrefs}")

            if CONFIG["show_progress_bar"] and self._cached_total > 0:
                parts.append(_progress_bar(self._cached_named, self._cached_total))
            elif CONFIG["show_func_count"] and self._cached_total > 0:
                parts.append(f"[{self._cached_named}/{self._cached_total}]")

            if CONFIG["show_time_on_func"] and self._tracking_func:
                parts.append(f"· {_fmt_duration(now - self._func_since)}")

            rpc.update(
                details     = details[:128],
                state       = "  ".join(parts)[:128],
                large_image = CONFIG["large_image"],
                large_text  = CONFIG["large_text"],
                start       = self.start_time,
            )

        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
            self._mark_disconnected()
        except BaseException as e:
            self._mark_disconnected()
            try:
                msg = str(e)
                if "Event loop is closed" not in msg:
                    log(f"RPC error: {msg}")
            except BaseException:
                pass


# =============================================================================
# Entry point
# =============================================================================

def PLUGIN_ENTRY():
    return DiscordRPCPlugin()
