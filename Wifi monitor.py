import json
import os
import platform
import re
import subprocess
import sys
import threading
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_FILE = os.path.join(BASE_DIR, "wifi_outages.json")
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")

PING_INTERVAL_SEC = 3
PING_TIMEOUT_MS = 1000
FAILS_TO_MARK_DISCONNECTED = 2  # 연속 실패 횟수
HTTP_PORT = 8765

IS_WINDOWS = platform.system() == "Windows"
IS_MAC = platform.system() == "Darwin"


SSID_UNKNOWN = object()

_lock = threading.Lock()


def detect_default_gateway():
    """OS별 명령으로 기본 게이트웨이(공유기) IP를 찾는다."""
    try:
        if IS_WINDOWS:
            out = subprocess.check_output(
                ["ipconfig"], text=True, encoding="cp949", errors="ignore"
            )
            lines = out.splitlines()
            for i, line in enumerate(lines):
                if "Default Gateway" in line or "기본 게이트웨이" in line:
                    for candidate_line in [line] + lines[i + 1 : i + 3]:
                        m = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", candidate_line)
                        if m:
                            return m.group(1)
        elif IS_MAC:
            out = subprocess.check_output(
                ["route", "-n", "get", "default"], text=True, errors="ignore"
            )
            m = re.search(r"gateway:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", out)
            if m:
                return m.group(1)
        else:
            out = subprocess.check_output(["ip", "route"], text=True, errors="ignore")
            m = re.search(r"default via (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", out)
            if m:
                return m.group(1)
    except Exception:
        pass
    return None


def _get_mac_ssid():
    """macOS: networksetup으로 SSID 조회. 실패/미지원이면 SSID_UNKNOWN."""
    try:
        hw = subprocess.check_output(
            ["networksetup", "-listallhardwareports"], text=True, errors="ignore"
        )
    except Exception:
        return SSID_UNKNOWN

    device = None
    lines = hw.splitlines()
    for i, line in enumerate(lines):
        if "Wi-Fi" in line or "AirPort" in line:
            for nxt in lines[i : i + 3]:
                m = re.match(r"Device:\s*(\S+)", nxt.strip())
                if m:
                    device = m.group(1)
                    break
            if device:
                break
    if not device:
        return SSID_UNKNOWN

    try:
        out = subprocess.check_output(
            ["networksetup", "-getairportnetwork", device], text=True, errors="ignore"
        )
    except Exception:
        return SSID_UNKNOWN

    if "not associated" in out.lower():
        return None  # 와이파이 미연결
    m = re.search(r"Current Wi-Fi Network:\s*(.+)", out)
    if m:
        ssid = m.group(1).strip()
        return ssid if ssid else SSID_UNKNOWN
    return SSID_UNKNOWN


def get_current_ssid():
    """현재 연결된 와이파이 SSID.
    반환값: SSID 문자열 / None(미연결로 확인됨) / SSID_UNKNOWN(이 환경에서는 확인 불가)
    """
    try:
        if IS_WINDOWS:
            out = subprocess.check_output(
                ["netsh", "wlan", "show", "interfaces"],
                text=True, encoding="cp949", errors="ignore",
            )
            for line in out.splitlines():
                stripped = line.strip()
                if stripped.upper().startswith("BSSID"):
                    continue
                m = re.match(r"SSID\s*:\s*(.*)$", stripped)
                if m:
                    ssid = m.group(1).strip()
                    return ssid if ssid else None
            return None
        elif IS_MAC:
            return _get_mac_ssid()
        else:
            out = subprocess.check_output(["iwgetid", "-r"], text=True, errors="ignore")
            ssid = out.strip()
            return ssid if ssid else None
    except Exception:
        return SSID_UNKNOWN


def load_config():
    cfg = {"gateway": "auto", "interval_sec": PING_INTERVAL_SEC, "target_ssid": ""}
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                cfg.update(json.load(f))
        except Exception:
            pass
    return cfg


def load_data():
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {"records": [], "ongoing": None}


def save_data(data):
    tmp = DATA_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, DATA_FILE)


STATE = {
    "gateway": None,
    "target_ssid": "",
    "current_ssid": None,
    "ssid_check_ok": True,
    "connected": True,
    "data": load_data(),
    "last_checked": None,
}


def ping_once(ip):
    try:
        if IS_WINDOWS:
            cmd = ["ping", "-n", "1", "-w", str(PING_TIMEOUT_MS), ip]
            kwargs = {"creationflags": subprocess.CREATE_NO_WINDOW} if hasattr(subprocess, "CREATE_NO_WINDOW") else {}
        elif IS_MAC:
            cmd = ["ping", "-c", "1", "-W", str(PING_TIMEOUT_MS), ip]
            kwargs = {}
        else:
            cmd = ["ping", "-c", "1", "-W", str(max(1, PING_TIMEOUT_MS // 1000)), ip]
            kwargs = {}
        result = subprocess.run(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=(PING_TIMEOUT_MS / 1000.0) + 2, **kwargs,
        )
        return result.returncode == 0
    except Exception:
        return False


def now_iso():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def monitor_loop():
    cfg = load_config()
    gateway = cfg.get("gateway", "auto")
    if not gateway or gateway == "auto":
        detected = detect_default_gateway()
        gateway = detected or "8.8.8.8"
        if not detected:
            print("[경고] 게이트웨이 IP를 자동으로 찾지 못해 8.8.8.8로 대체합니다. config.json에서 직접 지정 가능.")

    target_ssid = (cfg.get("target_ssid") or "").strip()

    with _lock:
        STATE["gateway"] = gateway
        STATE["target_ssid"] = target_ssid
        data = STATE["data"]
        # 프로그램이 재시작됐다면 원래 시작 시간 이어서 기록
        STATE["connected"] = data.get("ongoing") is None

    ssid_check_ok = False
    if target_ssid:
        probe = get_current_ssid()
        ssid_check_ok = probe is not SSID_UNKNOWN
        if not ssid_check_ok:
            print(f"[알림] 이 환경에서는 와이파이 SSID를 확인할 수 없어 '{target_ssid}' 지정은 무시하고 " f"게이트웨이 응답만으로 감시합니다.")

    with _lock:
        STATE["ssid_check_ok"] = ssid_check_ok

    if target_ssid and ssid_check_ok:
        print(f"[시작] '{target_ssid}' 와이파이 + 게이트웨이 {gateway} 를 {PING_INTERVAL_SEC}초마다 감시. http://127.0.0.1:{HTTP_PORT}")
    else:
        print(f"[시작] 게이트웨이 {gateway} 를 {PING_INTERVAL_SEC}초마다 감시. http://127.0.0.1:{HTTP_PORT}")

    consecutive_fails = 0

    while True:
        current_ssid = get_current_ssid() if (target_ssid and ssid_check_ok) else None
        if target_ssid and ssid_check_ok:
            # SSID가 다르면(다른 와이파이/핫스팟/유선랜/미접속) ping 없이 곧바로 끊김 처리
            ok = (current_ssid == target_ssid) and ping_once(gateway)
        else:
            ok = ping_once(gateway)

        with _lock:
            STATE["last_checked"] = now_iso()
            STATE["current_ssid"] = current_ssid
            data = STATE["data"]

            if ok:
                consecutive_fails = 0
                if not STATE["connected"]:
                    ongoing = data.get("ongoing")
                    end = now_iso()
                    if ongoing:
                        start_dt = datetime.fromisoformat(ongoing["start"])
                        end_dt = datetime.fromisoformat(end)
                        duration = max(0, int((end_dt - start_dt).total_seconds()))
                        data["records"].append(
                            {"start": ongoing["start"], "end": end, "duration_sec": duration}
                        )
                    data["ongoing"] = None
                    save_data(data)
                    STATE["connected"] = True
                    print(f"[복구] {end}")
            else:
                consecutive_fails += 1
                if STATE["connected"] and consecutive_fails >= FAILS_TO_MARK_DISCONNECTED:
                    start = now_iso()
                    data["ongoing"] = {"start": start}
                    save_data(data)
                    STATE["connected"] = False
                    print(f"[끊김] {start}")

        time.sleep(PING_INTERVAL_SEC)


def fmt_duration(sec):
    sec = int(sec)
    h, rem = divmod(sec, 3600)
    m, s = divmod(rem, 60)
    parts = []
    if h:
        parts.append(f"{h}시간")
    if m or h:
        parts.append(f"{m}분")
    parts.append(f"{s}초")
    return " ".join(parts)


def build_status_payload():
    with _lock:
        connected = STATE["connected"]
        gateway = STATE["gateway"]
        target_ssid = STATE["target_ssid"]
        current_ssid = STATE["current_ssid"]
        ssid_check_ok = STATE["ssid_check_ok"]
        last_checked = STATE["last_checked"]
        ongoing = STATE["data"].get("ongoing")
    return {
        "connected": connected,
        "gateway": gateway,
        "target_ssid": target_ssid,
        "current_ssid": current_ssid,
        "ssid_check_ok": ssid_check_ok,
        "last_checked": last_checked,
        "current_outage_start": ongoing["start"] if ongoing else None,
    }


def build_history_payload():
    with _lock:
        records = list(STATE["data"]["records"])
    ranked = sorted(records, key=lambda r: r["duration_sec"], reverse=True)
    total_outages = len(records)
    total_downtime = sum(r["duration_sec"] for r in records)
    longest = ranked[0]["duration_sec"] if ranked else 0
    avg = (total_downtime / total_outages) if total_outages else 0
    for i, r in enumerate(ranked):
        r["rank"] = i + 1
        r["duration_human"] = fmt_duration(r["duration_sec"])
    return {
        "ranking": ranked,
        "stats": {
            "total_outages": total_outages,
            "total_downtime_sec": total_downtime,
            "total_downtime_human": fmt_duration(total_downtime),
            "longest_sec": longest,
            "longest_human": fmt_duration(longest),
            "avg_sec": int(avg),
            "avg_human": fmt_duration(avg),
        },
    }


HTML_PAGE = """<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<title>와이파이 끊김 감시</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  :root{
    --bg:#0b0f14; --card:#121821; --border:#212a35; --text:#e6edf3; --muted:#8b98a5;
    --ok:#3fb950; --bad:#f85149; --accent:#58a6ff;
  }
  *{box-sizing:border-box;}
  body{
    margin:0; padding:24px; background:var(--bg); color:var(--text);
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Malgun Gothic",sans-serif;
  }
  h1{font-size:20px; margin:0 0 4px;}
  .sub{color:var(--muted); font-size:13px; margin-bottom:20px;}
  .status{
    display:flex; align-items:center; gap:12px; padding:18px 20px; border-radius:12px;
    border:1px solid var(--border); background:var(--card); margin-bottom:20px;
  }
  .dot{width:14px; height:14px; border-radius:50%; flex-shrink:0;}
  .dot.ok{background:var(--ok); box-shadow:0 0 8px var(--ok);}
  .dot.bad{background:var(--bad); box-shadow:0 0 8px var(--bad);}
  .status-text{font-size:16px; font-weight:600;}
  .status-detail{color:var(--muted); font-size:13px; margin-top:2px;}
  .cards{display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px; margin-bottom:24px;}
  .card{background:var(--card); border:1px solid var(--border); border-radius:12px; padding:14px 16px;}
  .card .label{color:var(--muted); font-size:12px; margin-bottom:6px;}
  .card .value{font-size:18px; font-weight:700;}
  table{width:100%; border-collapse:collapse; background:var(--card); border:1px solid var(--border); border-radius:12px; overflow:hidden;}
  th,td{padding:10px 14px; text-align:left; font-size:13px; border-bottom:1px solid var(--border);}
  th{color:var(--muted); font-weight:600; font-size:12px;}
  tr:last-child td{border-bottom:none;}
  .rank1{color:#f0b429; font-weight:700;}
  .rank2{color:#c9d1d9; font-weight:700;}
  .rank3{color:#cd7f32; font-weight:700;}
  .empty{color:var(--muted); padding:24px; text-align:center;}
  .footer{color:var(--muted); font-size:12px; margin-top:20px;}
</style>
</head>
<body>
  <h1>📡 와이파이 끊김 감시</h1>
  <div class="sub" id="gateway-line">게이트웨이 확인 중…</div>

  <div class="status">
    <div class="dot ok" id="dot"></div>
    <div>
      <div class="status-text" id="status-text">확인 중…</div>
      <div class="status-detail" id="status-detail"></div>
    </div>
  </div>

  <div class="cards">
    <div class="card"><div class="label">총 끊김 횟수</div><div class="value" id="c-count">-</div></div>
    <div class="card"><div class="label">총 끊긴 시간</div><div class="value" id="c-total">-</div></div>
    <div class="card"><div class="label">최장 끊김</div><div class="value" id="c-longest">-</div></div>
    <div class="card"><div class="label">평균 끊김</div><div class="value" id="c-avg">-</div></div>
  </div>

  <table>
    <thead>
      <tr><th>순위</th><th>시작 시각</th><th>종료 시각</th><th>지속 시간</th></tr>
    </thead>
    <tbody id="ranking-body">
      <tr><td colspan="4" class="empty">기록 불러오는 중…</td></tr>
    </tbody>
  </table>


<script>
let outageStart = null;

function fmtDuration(totalSec){
  totalSec = Math.max(0, Math.floor(totalSec));
  const h = Math.floor(totalSec/3600);
  const m = Math.floor((totalSec%3600)/60);
  const s = totalSec%60;
  let parts = [];
  if(h) parts.push(h+"시간");
  if(h||m) parts.push(m+"분");
  parts.push(s+"초");
  return parts.join(" ");
}

async function refreshStatus(){
  try{
    const res = await fetch("/api/status");
    const d = await res.json();
    let line = "감시 대상(게이트웨이): " + (d.gateway || "-");
    if(d.target_ssid){
      if(d.ssid_check_ok){
        line += " · 지정 와이파이: " + d.target_ssid + " (현재: " + (d.current_ssid || "미접속") + ")";
      } else {
        line += " · 이 기기에서는 SSID 확인 불가 — 게이트웨이 응답만으로 판단 중";
      }
    }
    line += (d.last_checked ? " · " + new Date(d.last_checked).toLocaleTimeString("ko-KR") + " 마지막 확인" : "");
    document.getElementById("gateway-line").textContent = line;
    const dot = document.getElementById("dot");
    const st = document.getElementById("status-text");
    const detail = document.getElementById("status-detail");
    if(d.connected){
      dot.className = "dot ok";
      st.textContent = "🟢 연결됨";
      detail.textContent = "";
      outageStart = null;
    } else {
      dot.className = "dot bad";
      st.textContent = "🔴 끊김";
      outageStart = d.current_outage_start ? new Date(d.current_outage_start) : null;
    }
  }catch(e){
    document.getElementById("status-text").textContent = "서버에 연결할 수 없음";
  }
}

function tickElapsed(){
  if(outageStart){
    const sec = (Date.now() - outageStart.getTime())/1000;
    document.getElementById("status-detail").textContent = "경과 시간: " + fmtDuration(sec);
  }
}

async function refreshHistory(){
  try{
    const res = await fetch("/api/history");
    const d = await res.json();
    document.getElementById("c-count").textContent = d.stats.total_outages + "회";
    document.getElementById("c-total").textContent = d.stats.total_downtime_human;
    document.getElementById("c-longest").textContent = d.stats.longest_human;
    document.getElementById("c-avg").textContent = d.stats.avg_human;

    const body = document.getElementById("ranking-body");
    if(d.ranking.length === 0){
      body.innerHTML = '<tr><td colspan="4" class="empty">아직 기록된 끊김이 없습니다.</td></tr>';
      return;
    }
    body.innerHTML = d.ranking.map(r => {
      const cls = r.rank===1 ? "rank1" : r.rank===2 ? "rank2" : r.rank===3 ? "rank3" : "";
      const startStr = new Date(r.start).toLocaleString("ko-KR");
      const endStr = new Date(r.end).toLocaleString("ko-KR");
      return `<tr><td class="${cls}">${r.rank}</td><td>${startStr}</td><td>${endStr}</td><td>${r.duration_human}</td></tr>`;
    }).join("");
  }catch(e){}
}

refreshStatus(); refreshHistory();
setInterval(refreshStatus, 2000);
setInterval(refreshHistory, 5000);
setInterval(tickElapsed, 500);
</script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # 요청 로그를 콘솔에 남기지 않음

    def _send_json(self, payload):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            body = HTML_PAGE.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/api/status":
            self._send_json(build_status_payload())
        elif self.path == "/api/history":
            self._send_json(build_history_payload())
        else:
            self.send_response(404)
            self.end_headers()


def run_server():
    server = ThreadingHTTPServer(("127.0.0.1", HTTP_PORT), Handler)
    server.serve_forever()


if __name__ == "__main__":
    t = threading.Thread(target=monitor_loop, daemon=True)
    t.start()
    try:
        run_server()
    except KeyboardInterrupt:
        print("\n[종료]")
        sys.exit(0)