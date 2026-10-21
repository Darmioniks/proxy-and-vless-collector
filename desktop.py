import os
import re
import socket
import sys
import threading
import time
import urllib.parse


APP_NAME = "Proxy Manager"
HAPP_SUBSCRIPTION_URL = (
    "https://raw.githubusercontent.com/"
    "Darmioniks/proxy-and-vless-collector/main/vless_filtered.txt"
)


def app_data_dir():
    if sys.platform.startswith("win"):
        root = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    else:
        root = os.environ.get("XDG_DATA_HOME") or os.path.join(
            os.path.expanduser("~"), ".local", "share"
        )
    path = os.path.join(root, "Darmioniks", "ProxyManager")
    os.makedirs(path, exist_ok=True)
    return path


PORT_FILE = "subscription_port.txt"


def load_saved_port():
    path = os.path.join(app_data_dir(), PORT_FILE)
    try:
        with open(path, encoding="utf-8") as fh:
            port = int(fh.read().strip())
    except (OSError, ValueError):
        return None
    return port if 1 <= port <= 65535 else None


def save_port(port):
    path = os.path.join(app_data_dir(), PORT_FILE)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(str(port))


def choose_port():
    """Stable across launches: PM_SUB_PORT, then the saved port, then a free one."""
    env = os.environ.get("PM_SUB_PORT")
    candidates = []
    if env and env.isdigit():
        candidates.append(int(env))
    saved = load_saved_port()
    if saved and saved not in candidates:
        candidates.append(saved)
    for port in candidates:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.bind(("127.0.0.1", port))
            save_port(port)
            return port
        except OSError:
            continue
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    save_port(port)
    return port


def wait_server(port, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.25):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def happ_command():
    if not sys.platform.startswith("win"):
        return None
    try:
        import winreg

        with winreg.OpenKey(
            winreg.HKEY_CLASSES_ROOT, r"happ\shell\open\command"
        ) as key:
            command = winreg.QueryValueEx(key, None)[0]
        match = re.match(r'^"([^"]+)"', command or "")
        path = match.group(1) if match else (command or "").split(" ", 1)[0]
        return command if path and os.path.exists(path) else None
    except (OSError, ImportError):
        return None


def happ_link(subscription_url=HAPP_SUBSCRIPTION_URL):
    return f"happ://add/{subscription_url}"


def valid_local_subscription(url):
    parsed = urllib.parse.urlparse(url)
    return (
        parsed.scheme == "http"
        and parsed.hostname in ("127.0.0.1", "localhost")
        and parsed.path.startswith("/sub/")
    )


class DesktopApi:
    def get_state(self):
        return {
            "desktop": True,
            "happInstalled": bool(happ_command()),
            "subscriptionUrl": HAPP_SUBSCRIPTION_URL,
        }

    def open_happ(self, subscription_url=None):
        subscription_url = subscription_url or HAPP_SUBSCRIPTION_URL
        if subscription_url != HAPP_SUBSCRIPTION_URL and not valid_local_subscription(subscription_url):
            return {
                "ok": False,
                "error": "Некорректная ссылка подписки.",
                "subscriptionUrl": subscription_url,
            }
        if not happ_command():
            return {
                "ok": False,
                "error": "Happ не найден. Ссылка подписки скопирована в буфер обмена.",
                "subscriptionUrl": subscription_url,
            }
        try:
            os.startfile(happ_link(subscription_url))
            return {
                "ok": True,
                "message": "Happ открыт. Подтвердите добавление подписки в приложении.",
                "subscriptionUrl": subscription_url,
            }
        except OSError as err:
            return {
                "ok": False,
                "error": f"Не удалось открыть Happ: {err}",
                "subscriptionUrl": subscription_url,
            }

    def open_telegram_proxy(self, link):
        parsed = urllib.parse.urlparse(link)
        if parsed.scheme != "tg" or parsed.netloc != "proxy":
            return {"ok": False, "error": "Некорректная ссылка Telegram-прокси"}
        try:
            os.startfile(link)
            return {"ok": True}
        except OSError as err:
            return {"ok": False, "error": f"Не удалось открыть Telegram: {err}"}


def main():
    os.environ.setdefault("PM_DATA_DIR", app_data_dir())

    import uvicorn
    import webview

    from server import app

    port = choose_port()
    config = uvicorn.Config(
        app, host="127.0.0.1", port=port, log_level="warning", access_log=False
    )
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    if not wait_server(port):
        server.should_exit = True
        raise RuntimeError("Не удалось запустить внутренний сервер приложения")

    try:
        webview.create_window(
            APP_NAME,
            f"http://127.0.0.1:{port}/?desktop=1",
            js_api=DesktopApi(),
            width=1320,
            height=900,
            min_size=(1040, 680),
            background_color="#f4f1eb",
            text_select=True,
        )
        webview.start(debug=False)
    finally:
        server.should_exit = True
        thread.join(timeout=5)


if __name__ == "__main__":
    main()
