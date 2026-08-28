import os

from PyInstaller.utils.hooks import collect_submodules


binaries = []
if os.path.exists("xray.exe"):
    binaries.append(("xray.exe", "."))

a = Analysis(
    ["desktop.py"],
    pathex=[],
    binaries=binaries,
    datas=[("templates", "templates"), ("static", "static")],
    hiddenimports=collect_submodules("webview"),
    hookspath=[],
    runtime_hooks=[],
    excludes=["streamlit", "pandas"],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="ProxyManager",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
