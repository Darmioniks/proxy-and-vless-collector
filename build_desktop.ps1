$ErrorActionPreference = "Stop"

python -m pip install -r requirements-build.txt
python -m PyInstaller --clean --noconfirm desktop.spec

Write-Host "Готово: dist\ProxyManager.exe"
