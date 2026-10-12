"""GameRemoteController PC Server (P0: Python console).

Android(폰) -> Tailscale/LAN -> WS :45321 -> SendInput(scancode) -> MapleStory.

규격: docs 02-protocol.md, 04-pc-server.md, 05-security-tailscale-anticheat.md
  - phone -> pc: keydown/keyup/key/mouse_move/mouse_down/mouse_up/wheel/ping
  - pc -> phone: ack/hello/hello_ok/error (ack/pong만 회신)
  - SendInput + KEYEVENTF_SCANCODE, wVk=0 (pynput/pyautogui 금지: DirectInput 씹힘)
  - 관리자권한 + GetForegroundWindow가 게임일 때만 주입, 아니면 드롭 + error 회신(폰 토스트용)
  - 눌림 테이블: keydown->pressed, 5초 초과 자동 릴리즈, keydown 없는 keyup 드롭
  - 마우스 상대이동만, 휠 WHEEL_DELTA=120 배수
  - TCP_NODELAY=1, :45321 리슨
  - 로그: 주입 성공/드롭 카운트만. 키로깅 저장 금지 (코드명 출력 없음)
  - 수동 플레이용. 자동사냥/매크로 기능 없음.

실행:
  run-as-admin python server.py --port 45321
  # 최초 1회: 화면에 PIN 6자리 표시 -> 폰에서 입력 -> token.txt 저장
"""

from __future__ import annotations

import argparse
import asyncio
import ctypes
import json
import random
import socket
import sys
import time
from pathlib import Path

try:
    import websockets
    from websockets.asyncio.server import serve
except ImportError:  # pragma: no cover
    print("need 'websockets' package: pip install -r requirements.txt", file=sys.stderr)
    raise SystemExit(2)


# ---------------------------------------------------------------- scancode table
# (scancode, extended). Extended keys need KEYEVENTF_EXTENDEDKEY.
# Set 1 PS/2 scancodes, SendInput SCANCODE compatible.
SCAN: dict[str, tuple[int, bool]] = {
    # 기존 (프로토콜 문서 02)
    "Left": (0x4B, True),
    "Right": (0x4D, True),
    "Up": (0x48, True),
    "Down": (0x50, True),
    "Alt": (0x38, False),
    "Ctrl": (0x1D, False),
    "Z": (0x2C, False),
    "X": (0x2D, False),
    "Q": (0x10, False),
    "W": (0x11, False),
    "Insert": (0x52, True),
    "Home": (0x47, True),
    "PageUp": (0x49, True),
    "Delete": (0x53, True),
    "End": (0x4F, True),
    "PageDown": (0x51, True),
    "F1": (0x3B, False),
    "F2": (0x3C, False),
    "F3": (0x3D, False),
    "F4": (0x3E, False),
    "F5": (0x3F, False),
    "F6": (0x40, False),
    # 문자 A-Z
    "A": (0x1E, False),
    "B": (0x30, False),
    "C": (0x2E, False),
    "D": (0x20, False),
    "E": (0x12, False),
    "F": (0x21, False),
    "G": (0x22, False),
    "H": (0x23, False),
    "I": (0x17, False),
    "J": (0x24, False),
    "K": (0x25, False),
    "L": (0x26, False),
    "M": (0x32, False),
    "N": (0x31, False),
    "O": (0x18, False),
    "P": (0x19, False),
    "R": (0x13, False),
    "S": (0x1F, False),
    "T": (0x14, False),
    "U": (0x16, False),
    "V": (0x2F, False),
    "Y": (0x15, False),
    # 숫자 0-9
    "0": (0x0B, False),
    "1": (0x02, False),
    "2": (0x03, False),
    "3": (0x04, False),
    "4": (0x05, False),
    "5": (0x06, False),
    "6": (0x07, False),
    "7": (0x08, False),
    "8": (0x09, False),
    "9": (0x0A, False),
    # 기호
    "Minus": (0x0C, False),  # -
    "Equals": (0x0D, False),  # =
    "LBracket": (0x1A, False),  # [
    "RBracket": (0x1B, False),  # ]
    "Semicolon": (0x27, False),  # ;
    "Quote": (0x28, False),  # '
    "Backquote": (0x29, False),  # `
    "Backslash": (0x2B, False),  # \
    "Comma": (0x33, False),  # ,
    "Period": (0x34, False),  # .
    "Slash": (0x35, False),  # /
    "Space": (0x39, False),
    # 제어
    "Esc": (0x01, False),
    "Tab": (0x0F, False),
    "Backspace": (0x0E, False),
    "Enter": (0x1C, False),
    "Shift": (0x2A, False),  # left shift
    # F7-F12
    "F7": (0x41, False),
    "F8": (0x42, False),
    "F9": (0x43, False),
    "F10": (0x44, False),
    "F11": (0x57, False),
    "F12": (0x58, False),
}

MOUSE_BTN = {"left", "right", "middle"}

# ---------------------------------------------------------------- Win32 API
INPUT_KEYBOARD = 1
INPUT_MOUSE = 0
KEYEVENTF_EXTENDEDKEY = 0x0001
KEYEVENTF_KEYUP = 0x0002
KEYEVENTF_SCANCODE = 0x0008
MOUSEEVENTF_MOVE = 0x0001
MOUSEEVENTF_LEFTDOWN = 0x0002
MOUSEEVENTF_LEFTUP = 0x0004
MOUSEEVENTF_RIGHTDOWN = 0x0008
MOUSEEVENTF_RIGHTUP = 0x0010
MOUSEEVENTF_MIDDLEDOWN = 0x0020
MOUSEEVENTF_MIDDLEUP = 0x0040
MOUSEEVENTF_WHEEL = 0x0800
WHEEL_DELTA = 120

STUCK_TIMEOUT = 5.0  # keyup 없는 keydown 5초 초과시 자동 릴리즈


class KEYBDINPUT(ctypes.Structure):
    _fields_ = [
        ("wVk", ctypes.c_ushort),
        ("wScan", ctypes.c_ushort),
        ("dwFlags", ctypes.c_ulong),
        ("time", ctypes.c_ulong),
        ("dwExtraInfo", ctypes.c_void_p),
    ]


class MOUSEINPUT(ctypes.Structure):
    _fields_ = [
        ("dx", ctypes.c_long),
        ("dy", ctypes.c_long),
        ("mouseData", ctypes.c_ulong),
        ("dwFlags", ctypes.c_ulong),
        ("time", ctypes.c_ulong),
        ("dwExtraInfo", ctypes.c_void_p),
    ]


class _INPUT_UNION(ctypes.Union):
    _fields_ = [("ki", KEYBDINPUT), ("mi", MOUSEINPUT)]


class INPUT(ctypes.Structure):
    _fields_ = [("type", ctypes.c_ulong), ("u", _INPUT_UNION)]


_user32 = ctypes.windll.user32


def _send_input(inp: INPUT) -> bool:
    return _user32.SendInput(1, ctypes.byref(inp), ctypes.sizeof(INPUT)) == 1


def key_event(scancode: int, extended: bool, up: bool) -> bool:
    flags = KEYEVENTF_SCANCODE | (KEYEVENTF_EXTENDEDKEY if extended else 0) | (KEYEVENTF_KEYUP if up else 0)
    ki = KEYBDINPUT(wVk=0, wScan=scancode, dwFlags=flags, time=0, dwExtraInfo=None)
    return _send_input(INPUT(type=INPUT_KEYBOARD, u=_INPUT_UNION(ki=ki)))


def mouse_move(dx: int, dy: int) -> bool:
    mi = MOUSEINPUT(dx=dx, dy=dy, mouseData=0, dwFlags=MOUSEEVENTF_MOVE, time=0, dwExtraInfo=None)
    return _send_input(INPUT(type=INPUT_MOUSE, u=_INPUT_UNION(mi=mi)))


def mouse_button(btn: str, down: bool) -> bool:
    flag = {
        ("left", True): MOUSEEVENTF_LEFTDOWN,
        ("left", False): MOUSEEVENTF_LEFTUP,
        ("right", True): MOUSEEVENTF_RIGHTDOWN,
        ("right", False): MOUSEEVENTF_RIGHTUP,
        ("middle", True): MOUSEEVENTF_MIDDLEDOWN,
        ("middle", False): MOUSEEVENTF_MIDDLEUP,
    }[(btn, down)]
    mi = MOUSEINPUT(dx=0, dy=0, mouseData=0, dwFlags=flag, time=0, dwExtraInfo=None)
    return _send_input(INPUT(type=INPUT_MOUSE, u=_INPUT_UNION(mi=mi)))


def mouse_wheel(clicks: int) -> bool:
    mi = MOUSEINPUT(dx=0, dy=0, mouseData=ctypes.c_ulong(clicks * WHEEL_DELTA).value,
                    dwFlags=MOUSEEVENTF_WHEEL, time=0, dwExtraInfo=None)
    return _send_input(INPUT(type=INPUT_MOUSE, u=_INPUT_UNION(mi=mi)))


def foreground_title() -> str:
    hwnd = _user32.GetForegroundWindow()
    buf = ctypes.create_unicode_buffer(256)
    _user32.GetWindowTextW(hwnd, buf, 256)
    return buf.value or ""


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def lan_ips() -> list[str]:
    """수동 연결용 LAN IP 목록. 실패해도 빈 리스트 (카드가 죽으면 안 됨)."""
    ips: list[str] = []
    try:  # 기본 루트 기준 외부 연결용 주소 (패킷 안 보냄)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            cand = s.getsockname()[0]
            if cand and not cand.startswith("127."):
                ips.append(cand)
        finally:
            s.close()
    except Exception:
        pass
    try:
        for cand in socket.gethostbyname_ex(socket.gethostname())[2]:
            if cand.startswith("127.") or cand.startswith("169.254.") or cand in ips:
                continue
            ips.append(cand)
    except Exception:
        pass
    return ips


def tailscale_ip() -> str:
    """tailscale 설치 시 100.x 주소 반환, 없으면 ''. 실패해도 ''."""
    try:
        import subprocess

        out = subprocess.run(
            ["tailscale", "ip", "-4"], capture_output=True, text=True, timeout=5
        )
        if out.returncode == 0:
            for line in out.stdout.splitlines():
                line = line.strip()
                if line.startswith("100."):
                    return line
    except Exception:
        pass
    return ""


# ---------------------------------------------------------------- server
class Stats:
    def __init__(self) -> None:
        self.injected = 0
        self.dropped = 0
        self.lock = asyncio.Lock()

    async def add_injected(self) -> None:
        async with self.lock:
            self.injected += 1

    async def add_dropped(self) -> None:
        async with self.lock:
            self.dropped += 1

    async def snapshot(self) -> tuple[int, int]:
        async with self.lock:
            return self.injected, self.dropped


class GameServer:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.stats = Stats()
        self.pressed: dict[str, float] = {}  # code -> keydown monotonic time
        self.token = self._load_or_create_token()

    # -- token / PIN ---------------------------------------------------
    def _load_or_create_token(self) -> str:
        tf = Path(self.args.token_file)
        if tf.exists() and not self.args.regen_token:
            token = tf.read_text(encoding="utf-8").strip()
            if token:
                print(f"[auth] token loaded from {tf} (=len {len(token)})")
                return token
        pin = self.args.pin or f"{random.randint(0, 999999):06d}"
        if not (pin.isdigit() and len(pin) == 6):
            raise SystemExit("--pin must be 6 digits")
        tf.write_text(pin, encoding="utf-8")
        print(f"[auth] 새 PIN 발급, 저장: {tf} (노출시 --regen-token 으로 재발급)")
        return pin

    # -- 연결 정보 카드 (수동 연결용: 매 실행시 표시) -----------------------
    def print_connection_card(self) -> None:
        port = self.args.port
        try:
            hostname = socket.gethostname()
        except Exception:
            hostname = "?"
        lan = lan_ips()
        ts = tailscale_ip()
        bar = "=" * 56
        print(bar)
        print(" [연결 정보] 폰 'PC 연결' 화면에 아래를 입력하세요")
        print(f"  PC 이름 : {hostname}")
        if lan:
            for ip in lan:
                print(f"  LAN     : {ip}  →  ws://{ip}:{port}")
        else:
            print("  LAN     : (조회 실패) ipconfig로 확인")
        if ts:
            print(f"  Tailscale: {ts}  →  ws://{ts}:{port}")
        print(f"  포트    : {port} (고정)")
        print(f"  PIN     : {self.token}")
        print(f"  게임 창 : '{self.args.game_title}' (이 창이 포그라운드일 때만 주입)")
        print(f"  방화벽   : {port} Private 허용 필요")
        print(bar)

    # -- helpers --------------------------------------------------------
    def fg_ok(self) -> bool:
        if self.args.no_fg_check:
            return True
        try:
            return self.args.game_title.lower() in foreground_title().lower()
        except Exception:
            return False

    async def _inject_or_drop(self, ok: bool) -> None:
        if ok:
            await self.stats.add_injected()
        else:
            await self.stats.add_dropped()

    @staticmethod
    async def _reply(ws, obj: dict) -> None:
        """폰 토스트용 회신. 실패해도 무시 (이미 끊긴 소켓 등)."""
        try:
            await ws.send(json.dumps(obj))
        except Exception:
            pass

    def _do_key(self, code: str, up: bool) -> bool:
        entry = SCAN.get(code)
        if entry is None:
            return False
        sc, ext = entry
        if self.args.dry_run:
            return True
        return key_event(sc, ext, up)

    # -- message handling ------------------------------------------------
    async def handle(self, ws, msg: dict) -> None:
        t = msg.get("t")

        if t == "hello":
            token = str(msg.get("token", ""))
            if token != self.token:
                await ws.send(json.dumps({"t": "error", "reason": "unauthorized"}))
                await self.stats.add_dropped()
                await ws.close(code=4401, reason="unauthorized")
                return
            profile = str(msg.get("profile", ""))
            print(f"[hello] profile={profile} from {ws.remote_address}")
            await ws.send(json.dumps({"t": "hello_ok"}))
            return

        if t == "ping":
            await ws.send(json.dumps({"t": "ack", "id": msg.get("id", 0), "rtt": 0}))
            return

        # --- input messages: foreground gate (인위적 딜레이 없음, 사람 입력 그대로)
        if t in ("keydown", "keyup", "key", "mouse_move", "mouse_down", "mouse_up", "wheel"):
            if not self.fg_ok():
                await self.stats.add_dropped()
                # 폰에 토스트용 error 회신 후 드롭
                try:
                    await ws.send(json.dumps({"t": "error", "reason": "not_in_foreground"}))
                except Exception:
                    pass
                return

        if t == "keydown":
            code = str(msg.get("code", ""))
            if code not in SCAN:
                await self.stats.add_dropped()
                await self._reply(ws, {"t": "error", "reason": f"unknown_code:{code}"})
                return
            self.pressed[code] = time.monotonic()
            await self._inject_or_drop(self._do_key(code, up=False))
        elif t == "keyup":
            code = str(msg.get("code", ""))
            if code not in self.pressed:
                await self.stats.add_dropped()  # keydown 없는 keyup 드롭
                return
            self.pressed.pop(code, None)
            await self._inject_or_drop(self._do_key(code, up=True))
        elif t == "key":
            code = str(msg.get("code", ""))
            if code not in SCAN:
                await self.stats.add_dropped()
                await self._reply(ws, {"t": "error", "reason": f"unknown_code:{code}"})
                return
            ok1 = self._do_key(code, up=False)
            ok2 = self._do_key(code, up=True)
            await self._inject_or_drop(ok1 and ok2)
        elif t == "mouse_move":
            try:
                dx, dy = int(msg.get("dx", 0)), int(msg.get("dy", 0))
            except (TypeError, ValueError):
                await self.stats.add_dropped()
                return
            ok = True if self.args.dry_run else mouse_move(dx, dy)
            await self._inject_or_drop(ok)
        elif t in ("mouse_down", "mouse_up"):
            btn = str(msg.get("btn", "left"))
            if btn not in MOUSE_BTN:
                await self.stats.add_dropped()
                return
            down = t == "mouse_down"
            ok = True if self.args.dry_run else mouse_button(btn, down)
            await self._inject_or_drop(ok)
        elif t == "wheel":
            try:
                delta = int(msg.get("delta", 0))
            except (TypeError, ValueError):
                await self.stats.add_dropped()
                return
            clicks = int(round(delta / WHEEL_DELTA))
            if clicks == 0:
                await self.stats.add_dropped()
                return
            ok = True if self.args.dry_run else mouse_wheel(clicks)
            await self._inject_or_drop(ok)
        else:
            await self.stats.add_dropped()

    async def auto_release_loop(self) -> None:
        """keyup 없는 keydown 5초 초과시 서버가 자동 릴리즈 (걸림 방지)."""
        while True:
            await asyncio.sleep(1.0)
            now = time.monotonic()
            stuck = [c for c, ts in self.pressed.items() if now - ts > STUCK_TIMEOUT]
            for code in stuck:
                self.pressed.pop(code, None)
                self._do_key(code, up=True)
                await self.stats.add_injected()
                print(f"[auto-release] {len(stuck)} key(s) released (5s timeout)")

    async def summary_loop(self) -> None:
        while True:
            await asyncio.sleep(60.0)
            inj, drop = await self.stats.snapshot()
            print(f"[stats] injected={inj} dropped={drop}")

    async def on_client(self, ws) -> None:
        addr = ws.remote_address
        print(f"[conn] {addr}")
        # TCP_NODELAY=1
        try:
            sock = ws.transport.get_extra_info("socket")
            if sock is not None:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception:
            pass
        try:
            async for raw in ws:
                try:
                    msg = json.loads(raw)
                except json.JSONDecodeError:
                    await self.stats.add_dropped()
                    continue
                if not isinstance(msg, dict):
                    await self.stats.add_dropped()
                    continue
                await self.handle(ws, msg)
        except Exception as e:
            print(f"[conn] {addr} closed: {e}")
        finally:
            inj, drop = await self.stats.snapshot()
            print(f"[conn] {addr} bye (injected={inj} dropped={drop})")

    async def run(self) -> None:
        if not is_admin():
            print("[warn] 관리자권한이 아닙니다. elevated 게임에는 주입이 실패합니다. run-as-admin 권장.")
        if self.args.dry_run:
            print("[warn] --dry-run: 실제 SendInput 없이 파싱/검증만 수행합니다.")
        self.print_connection_card()
        print(f"[listen] ws://0.0.0.0:{self.args.port} (game_title='{self.args.game_title}')")
        asyncio.create_task(self.auto_release_loop())
        asyncio.create_task(self.summary_loop())
        async with serve(self.on_client, "0.0.0.0", self.args.port):
            await asyncio.get_running_loop().create_future()  # forever


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="GameRemoteController PC server (SendInput scancode)")
    p.add_argument("--port", type=int, default=45321)
    p.add_argument("--pin", default="", help="6-digit pairing PIN (default: auto-generate)")
    p.add_argument("--token-file", default="token.txt")
    p.add_argument("--regen-token", action="store_true", help="기존 토큰 무효화 후 재발급")
    p.add_argument("--game-title", default="MapleStory", help="포그라운드 체크용 창 제목 부분문자열")
    p.add_argument("--no-fg-check", action="store_true", help="포그라운드 체크 비활성화 (테스트용)")
    p.add_argument("--dry-run", action="store_true", help="SendInput 없이 검증만")
    return p.parse_args(argv)


def _pause_if_interactive() -> None:
    """더블클릭 실행 시 에러가 바로 닫혀 안 보이는 문제 방지: 콘솔이면 대기."""
    try:
        if sys.stdin.isatty():
            input("종료하려면 Enter를 누르세요...")
    except (EOFError, KeyboardInterrupt):
        pass


def main() -> None:
    args = parse_args()
    try:
        srv = GameServer(args)
        try:
            asyncio.run(srv.run())
        except KeyboardInterrupt:
            print("bye")
    except OSError as e:
        # 10048 = 포트 이미 사용 중 (기존 pc-server 중복 실행이 가장 흔함)
        if getattr(e, "winerror", None) == 10048 or getattr(e, "errno", None) == 10048 or "10048" in str(e):
            print(f"[error] 포트 {args.port}가 이미 사용 중입니다.", file=sys.stderr)
            print("        기존 pc-server.exe가 실행 중인지 확인하세요 (작업 관리자).", file=sys.stderr)
        else:
            import traceback
            traceback.print_exc()
        _pause_if_interactive()
        raise SystemExit(1)
    except Exception:
        import traceback
        traceback.print_exc()
        _pause_if_interactive()
        raise SystemExit(1)


if __name__ == "__main__":
    main()
