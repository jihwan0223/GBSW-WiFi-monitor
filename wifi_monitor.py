#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
와이파이 끊김 감지 & 랭킹 대시보드
게이트웨이(공유기)에 주기적으로 ping을 보내 연결 끊김/복구를 감지하고 지속 시간을 기록한다.
실행: python wifi_monitor.py  ->  http://127.0.0.1:8765
"""

import json
import os
import platform
import re
import socket
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
FAILS_TO_MARK_DISCONNECTED = 2  # 연속 실패 횟수 (순간 지연으로 인한 오탐 방지)
HTTP_PORT = 8765

# 학교/기관 네트워크는 보안상 게이트웨이로 가는 ICMP(ping)를 막아두는 경우가 많다.
# 그런 경우를 대비해, ping이 실패하면 공용 DNS 서버(53번 포트)로 TCP 연결을 시도해
# "인터넷 자체는 되는지"를 한 번 더 확인한다.
INTERNET_CHECK_HOSTS = ["1.1.1.1", "8.8.8.8"]

IS_WINDOWS = platform.system() == "Windows"
IS_MAC = platform.system() == "Darwin"

# get_current_ssid()가 이 값을 반환하면 "이 환경/OS 버전에서는 SSID를 확인할 방법이 없다"는 뜻
# (macOS 14.4+ 는 위치정보 권한 제약으로 커맨드라인에서 SSID를 못 가져오는 경우가 많음)
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
                    # IP가 같은 줄이 아니라 다음 줄에 나오는 경우가 있어 2줄까지 함께 확인
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
        return None  # 와이파이 미연결로 확인됨 (정상적으로 판별 가능한 상태)
    m = re.search(r"Current Wi-Fi Network:\s*(.+)", out)
    if m:
        ssid = m.group(1).strip()
        return ssid if ssid else SSID_UNKNOWN
    # macOS 14.4+ 에서는 위치정보 권한 제약으로 값이 안 나오는 경우가 있음
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
            return None  # SSID 줄 자체가 없으면 와이파이 미연결
        elif IS_MAC:
            return _get_mac_ssid()
        else:
            out = subprocess.check_output(["iwgetid", "-r"], text=True, errors="ignore")
            ssid = out.strip()
            return ssid if ssid else None
    except Exception:
        return SSID_UNKNOWN


def load_config():
    cfg = {
        "gateway": "auto",
        "interval_sec": PING_INTERVAL_SEC,
        "target_ssid": "",
        "quiet_hours_enabled": False,
        "quiet_hours_start": "01:00",
        "quiet_hours_end": "06:00",
    }
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
    # 원자적 저장 (쓰는 도중 중단돼도 파일이 깨지지 않도록 임시파일 -> rename)
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
    "quiet_hours_enabled": False,
    "quiet_hours_range": "",
    "in_quiet_hours": False,
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


def check_internet(timeout=1.0):
    """게이트웨이 ping이 막혀있는 네트워크(학교/기관 네트워크에서 흔함)를 대비한 대체 확인.
    공용 DNS 서버의 53번 포트로 TCP 연결을 시도해서 인터넷 자체가 되는지 확인한다."""
    for host in INTERNET_CHECK_HOSTS:
        try:
            with socket.create_connection((host, 53), timeout=timeout):
                return True
        except OSError:
            continue
    return False


def now_iso():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def parse_hhmm(s, default_minutes):
    try:
        h, m = s.split(":")
        return int(h) * 60 + int(m)
    except Exception:
        return default_minutes


def in_quiet_hours(now_dt, start_min, end_min):
    """start_min == end_min 이면 비활성화. 자정을 넘어가는 구간(예: 23:00~06:00)도 지원."""
    if start_min == end_min:
        return False
    cur = now_dt.hour * 60 + now_dt.minute
    if start_min < end_min:
        return start_min <= cur < end_min
    return cur >= start_min or cur < end_min


def monitor_loop():
    cfg = load_config()
    gateway = cfg.get("gateway", "auto")
    if not gateway or gateway == "auto":
        detected = detect_default_gateway()
        gateway = detected or "8.8.8.8"
        if not detected:
            print("[경고] 게이트웨이 IP를 자동으로 찾지 못해 8.8.8.8로 대체합니다. config.json에서 직접 지정 가능.")

    target_ssid = (cfg.get("target_ssid") or "").strip()

    quiet_enabled = bool(cfg.get("quiet_hours_enabled", False))
    quiet_start_str = cfg.get("quiet_hours_start", "01:00")
    quiet_end_str = cfg.get("quiet_hours_end", "06:00")
    quiet_start_min = parse_hhmm(quiet_start_str, 60)
    quiet_end_min = parse_hhmm(quiet_end_str, 360)

    with _lock:
        STATE["gateway"] = gateway
        STATE["target_ssid"] = target_ssid
        STATE["quiet_hours_enabled"] = quiet_enabled
        STATE["quiet_hours_range"] = f"{quiet_start_str}~{quiet_end_str}"
        STATE["in_quiet_hours"] = False
        data = STATE["data"]
        # 끊긴 상태에서 프로그램이 재시작됐다면 원래 시작 시각을 이어서 사용
        STATE["connected"] = data.get("ongoing") is None

    if quiet_enabled:
        print(f"{quiet_start_str}~{quiet_end_str} 사이에는 끊김을 기록하지 않습니다.")

    # SSID 확인이 이 환경에서 실제로 가능한지 시작할 때 한 번만 검사 (macOS는 OS 버전에 따라 불가능할 수 있음)
    ssid_check_ok = False
    if target_ssid:
        probe = get_current_ssid()
        ssid_check_ok = probe is not SSID_UNKNOWN
        if not ssid_check_ok:
            print(f"[알림] 이 환경에서는 와이파이 SSID를 확인할 수 없어 '{target_ssid}' 지정은 무시하고 "
                  f"게이트웨이 응답만으로 감시합니다.")

    with _lock:
        STATE["ssid_check_ok"] = ssid_check_ok

    if target_ssid and ssid_check_ok:
        print(f"[시작] '{target_ssid}' 와이파이 + 게이트웨이 {gateway} 를 {PING_INTERVAL_SEC}초마다 감시. http://127.0.0.1:{HTTP_PORT}")
    else:
        print(f"[시작] 게이트웨이 {gateway} 를 {PING_INTERVAL_SEC}초마다 감시. http://127.0.0.1:{HTTP_PORT}")

    consecutive_fails = 0

    while True:
        now_dt = datetime.now()
        quiet_now = quiet_enabled and in_quiet_hours(now_dt, quiet_start_min, quiet_end_min)

        with _lock:
            was_quiet = STATE["in_quiet_hours"]
            STATE["in_quiet_hours"] = quiet_now
            data = STATE["data"]

            if quiet_now and not was_quiet:
                # 야간 시간대 진입: 진행 중이던 끊김이 있으면 지금 시점으로 마감하고 이후는 기록하지 않음
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
                consecutive_fails = 0
                print(f"{now_iso()} 부터 감시를 중단합니다.")
            elif not quiet_now and was_quiet:
                consecutive_fails = 0
                print(f"{now_iso()} 부터 감시를 시작합니다.")

        if quiet_now:
            with _lock:
                STATE["last_checked"] = now_iso()
                STATE["current_ssid"] = None
            time.sleep(PING_INTERVAL_SEC)
            continue

        current_ssid = get_current_ssid() if (target_ssid and ssid_check_ok) else None
        # 게이트웨이 ping이 막힌 네트워크 대비: ping이 실패해도 공용 DNS 연결이 되면 "연결됨"으로 판단
        reachable = ping_once(gateway) or check_internet()
        if target_ssid and ssid_check_ok:
            # SSID가 다르면(다른 와이파이/핫스팟/유선랜/미접속) 곧바로 끊김 처리
            ok = (current_ssid == target_ssid) and reachable
        else:
            ok = reachable

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
        quiet_hours_enabled = STATE["quiet_hours_enabled"]
        quiet_hours_range = STATE["quiet_hours_range"]
        in_quiet_hours = STATE["in_quiet_hours"]
        ongoing = STATE["data"].get("ongoing")
    return {
        "connected": connected,
        "gateway": gateway,
        "target_ssid": target_ssid,
        "current_ssid": current_ssid,
        "ssid_check_ok": ssid_check_ok,
        "last_checked": last_checked,
        "current_outage_start": ongoing["start"] if ongoing else None,
        "quiet_hours_enabled": quiet_hours_enabled,
        "quiet_hours_range": quiet_hours_range,
        "in_quiet_hours": in_quiet_hours,
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


# 외부 리소스 없이 완전히 로컬에서 동작 (와이파이가 끊겨도 열림)
HTML_PAGE = """<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<title>와이파이 끊김 갤러리</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  *{box-sizing:border-box;}
  body{
    margin:0; background:#fff; color:#333; font-size:13px;
    font-family:"Apple SD Gothic Neo","Malgun Gothic","맑은 고딕","Dotum","돋움",sans-serif;
  }
  a{color:#333; text-decoration:none;}
  .topbar{background:#3b4890; height:42px;}
  .topbar .inner{max-width:980px; margin:0 auto; padding:0 12px; display:flex; align-items:center; height:42px;}
  .logo{color:#fff; font-weight:bold; font-size:20px; letter-spacing:-1px;}
  .logo span{color:#ffd400;}
  .wrap{max-width:980px; margin:0 auto; padding:16px 12px 40px;}

  .gall-head{border-bottom:2px solid #3b4890; padding-bottom:8px; display:flex; align-items:flex-end; justify-content:space-between; gap:8px; flex-wrap:wrap;}
  .gall-title{font-size:22px; font-weight:bold; color:#3b4890; letter-spacing:-1px;}
  .gall-title small{font-size:12px; color:#999; font-weight:normal; margin-left:6px; letter-spacing:0;}
  .gall-sub{color:#777; font-size:12px; margin:8px 0 12px; line-height:1.6; word-break:keep-all;}

  .tabs{display:flex; border-bottom:1px solid #ccc; margin-bottom:0;}
  .tabs div{padding:8px 14px; font-size:13px; color:#666; border:1px solid transparent; border-bottom:none; margin-bottom:-1px;}
  .tabs .on{color:#3b4890; font-weight:bold; border-color:#ccc; background:#fff;}
  .tab-row{display:flex; justify-content:space-between; align-items:flex-end; border-bottom:1px solid #ccc;}
  .tab-row .tabs{border-bottom:none;}
  .sort{display:flex; gap:4px; padding-bottom:5px;}
  .sort button{
    font:inherit; font-size:12px; color:#666; background:#fff; border:1px solid #ccc;
    padding:4px 10px; cursor:pointer; border-radius:2px; display:flex; align-items:center; gap:4px;
  }
  .sort button:hover{background:#f5f7fb;}
  .sort button.on{color:#fff; background:#3b4890; border-color:#3b4890; font-weight:bold;}
  .sort .arrow{font-size:10px;}

  .info-box{display:grid; grid-template-columns:repeat(4,1fr); border:1px solid #ccc; border-top:none; background:#f8f8f8; margin-bottom:14px;}
  .info-box div{padding:9px 10px; text-align:center; border-right:1px solid #e1e1e1;}
  .info-box div:last-child{border-right:none;}
  .info-box .k{color:#888; font-size:11px; display:block; margin-bottom:3px;}
  .info-box .v{color:#3b4890; font-weight:bold; font-size:14px;}

  table{width:100%; border-collapse:collapse; border-top:2px solid #3b4890; table-layout:fixed;}
  th{background:#fafafa; color:#555; font-weight:normal; font-size:12px; padding:8px 4px; border-bottom:1px solid #ccc;}
  td{padding:8px 4px; border-bottom:1px solid #eee; text-align:center; font-size:13px; color:#666; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;}
  td.title{text-align:left; padding-left:10px; color:#333;}
  tbody tr:hover td{background:#f5f7fb;}
  .col-no{width:60px;} .col-writer{width:110px;} .col-start,.col-end{width:140px;} .col-dur{width:100px;}

  tr.notice td{background:#fff8f8; font-weight:bold;}
  tr.notice.ok td{background:#f6fbf6;}
  tr.notice.night td{background:#f5f7fd;}
  .tag{display:inline-block; font-size:11px; font-weight:bold; color:#fff; padding:1px 6px; border-radius:2px; background:#d31900;}
  .tag.ok{background:#2c9c3d;}
  .tag.night{background:#3b4890;}
  .sub-detail{color:#d31900; font-weight:normal; margin-left:6px;}

  .best{display:inline-block; font-size:10px; color:#fff; background:#d31900; padding:0 4px; margin-right:5px; border-radius:2px; vertical-align:1px;}
  tr.r1 td.title{color:#d31900; font-weight:bold;}
  tr.r2 td.title{color:#e05a00; font-weight:bold;}
  tr.r3 td.title{color:#b8860b; font-weight:bold;}
  .cmt{color:#d31900; font-size:11px; margin-left:3px;}
  .writer{color:#333;}
  .ip{color:#999; font-size:11px;}
  .empty{color:#999; padding:30px 0 !important;}

  .footer{margin-top:24px; padding-top:12px; border-top:1px solid #ddd; color:#999; font-size:11px; text-align:center; line-height:1.7;}

  @media (max-width:640px){
    table{table-layout:auto;}
    th.col-writer,th.col-end,th.col-start,td.c-writer,td.c-end,td.c-start{display:none;}
    td.title{white-space:normal; line-height:1.4;}
    .info-box{grid-template-columns:repeat(2,1fr);}
    .info-box div:nth-child(2){border-right:none;}
    .info-box div:nth-child(-n+2){border-bottom:1px solid #e1e1e1;}
    td,th{font-size:12px;}
  }
</style>
</head>
<body>
  <div class="topbar"><div class="inner"><div class="logo">gbsw<span>inside</span></div></div></div>

  <div class="wrap">
    <div class="gall-head">
      <div class="gall-title">와이파이 끊김 갤러리<small>gbsw314</small></div>
    </div>
    <div class="gall-sub" id="gateway-line">게이트웨이 확인 중…</div>

    <div class="tab-row">
      <div class="tabs"><div class="on">전체글</div><div>개념글</div><div>공지</div></div>
      <div class="sort">
        <button type="button" id="sort-pop" class="on">인기순</button>
        <button type="button" id="sort-date">날짜순 <span class="arrow" id="date-arrow">▼</span></button>
      </div>
    </div>
    <div class="info-box">
      <div><span class="k">총 끊김 횟수</span><span class="v" id="c-count">-</span></div>
      <div><span class="k">총 끊긴 시간</span><span class="v" id="c-total">-</span></div>
      <div><span class="k">최장 끊김</span><span class="v" id="c-longest">-</span></div>
      <div><span class="k">평균 끊김</span><span class="v" id="c-avg">-</span></div>
    </div>

    <table>
      <thead>
        <tr><th class="col-no">순위</th><th>제목</th><th class="col-writer">글쓴이</th><th class="col-start">시작</th><th class="col-end">종료</th><th class="col-dur">지속</th></tr>
      </thead>
      <tbody>
        <tr class="notice" id="notice-row">
          <td><span class="tag" id="tag">공지</span></td>
          <td class="title" colspan="5"><span id="status-text">확인 중…</span><span class="sub-detail" id="status-detail"></span></td>
        </tr>
      </tbody>
      <tbody id="ranking-body">
        <tr><td colspan="6" class="empty">기록 불러오는 중…</td></tr>
      </tbody>
    </table>

    <div class="footer">
      이 갤러리는 기숙사 와이파이 끊김을 자동으로 기록합니다. 순위는 오래 끊긴 순입니다.<br>
      Copyright © gbswinside. All rights reserved.
    </div>
  </div>

<script>
let outageStart = null;
let records = [];
let sortMode = "pop";     // "pop" = 인기순(오래 끊긴 순), "date" = 날짜순
let dateDesc = true;      // 날짜순일 때 true = 최신순 ▼, false = 오래된순 ▲

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

function fmtDate(iso){
  const d = new Date(iso);
  const p = n => String(n).padStart(2,"0");
  return (d.getMonth()+1) + "." + p(d.getDate()) + " " + p(d.getHours()) + ":" + p(d.getMinutes()) + ":" + p(d.getSeconds());
}

async function refreshStatus(){
  try{
    const res = await fetch("/api/status");
    const d = await res.json();
    let line = "감시 대상: " + (d.gateway || "-");
    if(d.target_ssid){
      if(d.ssid_check_ok){
        line += " · 지정 와이파이: " + d.target_ssid + " (현재: " + (d.current_ssid || "미접속") + ")";
      } else {
        line += " · SSID 확인 불가 — 게이트웨이 응답으로 판단";
      }
    }
    if(d.last_checked) line += " · 마지막 확인 " + new Date(d.last_checked).toLocaleTimeString("ko-KR");
    if(d.quiet_hours_enabled) line += " · 미감시 " + d.quiet_hours_range;
    document.getElementById("gateway-line").textContent = line;

    const row = document.getElementById("notice-row");
    const tag = document.getElementById("tag");
    const st = document.getElementById("status-text");
    const detail = document.getElementById("status-detail");
    if(d.in_quiet_hours){
      row.className = "notice night"; tag.className = "tag night"; tag.textContent = "야간";
      st.textContent = "지금은 미감시 시간대임 (" + d.quiet_hours_range + ")";
      detail.textContent = ""; outageStart = null;
    } else if(d.connected){
      row.className = "notice ok"; tag.className = "tag ok"; tag.textContent = "정상";
      st.textContent = "와이파이 정상 연결 중";
      detail.textContent = ""; outageStart = null;
    } else {
      row.className = "notice"; tag.className = "tag"; tag.textContent = "속보";
      st.textContent = "[속보] 와이파이 지금 끊김";
      outageStart = d.current_outage_start ? new Date(d.current_outage_start) : null;
    }
  }catch(e){
    document.getElementById("status-text").textContent = "서버에 연결할 수 없음";
  }
}

function tickElapsed(){
  if(outageStart){
    const sec = (Date.now() - outageStart.getTime())/1000;
    document.getElementById("status-detail").textContent = "경과 " + fmtDuration(sec);
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

    records = d.ranking;
    renderList();
  }catch(e){}
}

function renderList(){
  const body = document.getElementById("ranking-body");
  if(records.length === 0){
    body.innerHTML = '<tr><td colspan="6" class="empty">등록된 게시물이 없습니다.</td></tr>';
    return;
  }
  const list = records.slice();
  if(sortMode === "date"){
    list.sort((a, b) => {
      const diff = new Date(a.start) - new Date(b.start);
      return dateDesc ? -diff : diff;
    });
  } else {
    list.sort((a, b) => a.rank - b.rank);
  }
  body.innerHTML = list.map(r => {
    const cls = r.rank<=3 ? "r"+r.rank : "";
    const best = r.rank<=3 ? '<span class="best">개념</span>' : "";
    const mins = Math.floor(r.duration_sec/60);
    return `<tr class="${cls}">
      <td>${r.rank}</td>
      <td class="title">${best}와이파이 ${r.duration_human} 동안 끊김<span class="cmt">[${mins}]</span></td>
      <td class="c-writer"><span class="writer">ㅇㅇ</span> <span class="ip">(172.28)</span></td>
      <td class="c-start">${fmtDate(r.start)}</td>
      <td class="c-end">${fmtDate(r.end)}</td>
      <td>${r.duration_human}</td>
    </tr>`;
  }).join("");
}

function updateSortButtons(){
  document.getElementById("sort-pop").className = sortMode === "pop" ? "on" : "";
  document.getElementById("sort-date").className = sortMode === "date" ? "on" : "";
  document.getElementById("date-arrow").textContent = dateDesc ? "▼" : "▲";
  document.getElementById("sort-date").title = dateDesc ? "최신순 (누르면 오래된순)" : "오래된순 (누르면 최신순)";
}

document.getElementById("sort-pop").onclick = () => {
  sortMode = "pop";
  updateSortButtons(); renderList();
};
document.getElementById("sort-date").onclick = () => {
  if(sortMode === "date") dateDesc = !dateDesc;  // 이미 날짜순이면 화살표 방향 전환
  else sortMode = "date";
  updateSortButtons(); renderList();
};
updateSortButtons();

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