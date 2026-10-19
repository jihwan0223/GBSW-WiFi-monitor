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
MERGE_GAP_SEC = 60  # 복구 후 이 시간 안에 다시 끊기면 한 번의 끊김으로 합침
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


def gap_sec(earlier_iso, later_iso):
    return (datetime.fromisoformat(later_iso) - datetime.fromisoformat(earlier_iso)).total_seconds()


def merge_short_gaps(records):
    merged = []
    for r in sorted(records, key=lambda r: datetime.fromisoformat(r["start"])):
        if merged and gap_sec(merged[-1]["end"], r["start"]) < MERGE_GAP_SEC:
            last = merged[-1]
            if gap_sec(last["end"], r["end"]) > 0:
                last["end"] = r["end"]
            last["duration_sec"] = max(0, int(gap_sec(last["start"], last["end"])))
        else:
            merged.append(dict(r))
    return merged


def load_data():
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            data = None
        if data is not None:
            try:
                data["records"] = merge_short_gaps(data.get("records", []))
            except Exception:
                pass
            return data
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
                    records = data["records"]
                    if records and gap_sec(records[-1]["end"], start) < MERGE_GAP_SEC:
                        start = records.pop()["start"]
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
  button{font:inherit;}
  .topbar{background:#3b4890;}
  .topbar .inner{max-width:980px; margin:0 auto; padding:0 12px; display:flex; align-items:center; height:42px;}
  .logo{color:#fff; font-weight:bold; font-size:20px; letter-spacing:-1px;}
  .logo span{color:#ffd400;}
  .gnb{background:#29367c; border-bottom:1px solid #1f2a63;}
  .gnb .inner{max-width:980px; margin:0 auto; padding:0 12px; display:flex; gap:18px; height:32px; align-items:center; overflow:hidden; white-space:nowrap;}
  .gnb span{color:#c9cfee; font-size:12px;}
  .gnb span.on{color:#fff; font-weight:bold;}
  .wrap{max-width:980px; margin:0 auto; padding:16px 12px 40px;}

  .gall-head{border-bottom:2px solid #3b4890; padding-bottom:8px; margin-bottom:12px; display:flex; align-items:flex-end; justify-content:space-between; gap:8px; flex-wrap:wrap;}
  .gall-title{font-size:22px; font-weight:bold; color:#3b4890; letter-spacing:-1px;}

  .tab-row{display:flex; justify-content:space-between; align-items:flex-end; border-bottom:1px solid #ccc;}
  .tabs{display:flex;}
  .tabs button{padding:8px 14px; font-size:13px; color:#666; background:none; border:1px solid transparent; border-bottom:none; margin-bottom:-1px; cursor:pointer;}
  .tabs button.on{color:#3b4890; font-weight:bold; border-color:#ccc; background:#fff;}
  .tabs .cnt{color:#d31900; font-size:11px; font-weight:normal; margin-left:2px;}
  .sort{display:flex; gap:4px; padding-bottom:5px;}
  .sort button{
    font-size:12px; color:#666; background:#fff; border:1px solid #ccc;
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

  .list{width:100%; border-collapse:collapse; border-top:2px solid #3b4890; table-layout:fixed;}
  .list th{background:#fafafa; color:#555; font-weight:normal; font-size:12px; padding:8px 4px; border-bottom:1px solid #ccc;}
  .list td{padding:8px 4px; border-bottom:1px solid #eee; text-align:center; font-size:13px; color:#666; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;}
  .list td.title{text-align:left; padding-left:10px;}
  .list td.title a{color:#333;}
  .list td.title a:visited{color:#770088;}
  .list td.title a:hover{text-decoration:underline;}
  .list tbody tr:hover td{background:#f5f7fb;}
  .list tr.cur td{background:#eef1fa;}
  .list tr.cur td.c-no{color:#3b4890; font-weight:bold;}
  .col-no{width:60px;} .col-head{width:64px;} .col-writer{width:110px;} .col-date{width:90px;} .col-time{width:70px;} .col-dur{width:100px;}
  .c-head{color:#888 !important; font-size:12px !important;}
  .c-head.big{color:#d31900 !important; font-weight:bold;}

  .ico{display:inline-block; width:11px; height:13px; margin-right:6px; vertical-align:-2px; border:1px solid #9aa3c3; border-radius:1px;
       background:repeating-linear-gradient(#fff 0 2px,#b8bfd8 2px 3px) 2px 2px/5px 8px no-repeat #fff;}
  .ico.best{border-color:#d31900; background-color:#fff3f0;}

  tr.notice td{background:#fff8f8; font-weight:bold;}
  tr.notice.ok td{background:#f6fbf6;}
  tr.notice.night td{background:#f5f7fd;}
  .tag{display:inline-block; font-size:11px; font-weight:bold; color:#fff; padding:1px 6px; border-radius:2px; background:#d31900;}
  .tag.ok{background:#2c9c3d;}
  .tag.night{background:#3b4890;}
  .sub-detail{color:#d31900; font-weight:normal; margin-left:6px;}

  .best{display:inline-block; font-size:10px; color:#fff; background:#d31900; padding:0 4px; margin-right:5px; border-radius:2px; vertical-align:1px;}
  tr.r1 td.title a{color:#d31900; font-weight:bold;}
  tr.r2 td.title a{color:#e05a00; font-weight:bold;}
  tr.r3 td.title a{color:#b8860b; font-weight:bold;}
  .cmt{color:#d31900; font-size:11px; margin-left:3px;}
  .writer{color:#333;}
  .ip{color:#999; font-size:11px;}
  .empty{color:#999; padding:30px 0 !important;}

  .paging{display:flex; justify-content:center; gap:2px; margin:16px 0 0; flex-wrap:wrap;}
  .paging button{min-width:26px; padding:3px 6px; background:none; border:1px solid transparent; color:#333; cursor:pointer; font-size:13px;}
  .paging button:hover{text-decoration:underline;}
  .paging button.on{color:#d31900; font-weight:bold; border-color:#ccc;}

  .view{border-top:2px solid #3b4890; margin-bottom:24px;}
  .view-head{padding:12px 10px 10px; border-bottom:1px solid #ddd;}
  .view-title{font-size:17px; font-weight:bold; color:#333; margin:0 0 8px; letter-spacing:-0.5px; word-break:keep-all;}
  .view-title .h{color:#3b4890; margin-right:4px;}
  .view-meta{display:flex; justify-content:space-between; gap:6px; flex-wrap:wrap; color:#999; font-size:12px;}
  .view-meta .bar{color:#ddd; margin:0 6px;}
  .view-body{padding:22px 12px 6px; line-height:1.9; font-size:14px; color:#222;}
  .view-body p{margin:0 0 4px;}
  .view-body .red{color:#d31900;}
  .detail{border-collapse:collapse; border-top:1px solid #bbb; width:100%; max-width:520px; margin:20px 0 6px; font-size:13px;}
  .detail th{width:110px; text-align:left; font-weight:normal; color:#666; background:#f8f8f8; padding:7px 10px; border-bottom:1px solid #e5e5e5;}
  .detail td{padding:7px 10px; border-bottom:1px solid #e5e5e5; color:#333;}
  .detail .gray{color:#999; font-size:12px;}
  .tl-wrap{max-width:520px; margin:18px 0 10px;}
  .tl-label{font-size:12px; color:#666; margin-bottom:4px;}
  .tl{position:relative; height:22px; background:#eef0f6; border:1px solid #d5d9e8;}
  .tl .q{position:absolute; top:0; bottom:0; background:repeating-linear-gradient(45deg,#d8dcea 0 3px,#eef0f6 3px 7px);}
  .tl a{position:absolute; top:0; bottom:0; min-width:3px; background:#f2a493;}
  .tl a.me{background:#d31900; z-index:1;}
  .tl-scale{display:flex; justify-content:space-between; font-size:11px; color:#999; margin-top:3px;}
  .recom{display:flex; justify-content:center; gap:10px; padding:22px 0; border-bottom:1px solid #eee;}
  .recom button{width:100px; border:1px solid #ccc; background:#fff; border-radius:4px; padding:8px 0 7px; cursor:pointer; color:#555; font-size:12px;}
  .recom button .n{display:block; font-size:19px; font-weight:bold; color:#d31900; margin-bottom:2px;}
  .recom button.down .n{color:#666;}
  .recom button.on{border-color:#d31900; background:#fff5f3;}
  .recom button.down.on{border-color:#666; background:#f3f3f3;}
  .view-nav a{display:flex; gap:12px; padding:8px 10px; border-bottom:1px solid #eee; overflow:hidden; white-space:nowrap; text-overflow:ellipsis;}
  .view-nav a:hover{background:#f5f7fb;}
  .view-nav .k{color:#999; flex:none; width:50px;}
  .view-btns{display:flex; justify-content:flex-end; padding-top:10px;}
  .view-btns a{border:1px solid #3b4890; background:#3b4890; color:#fff; font-weight:bold; padding:5px 16px; border-radius:2px; font-size:12px;}

  .footer{margin-top:24px; padding-top:12px; border-top:1px solid #ddd; color:#999; font-size:11px; text-align:center; line-height:1.7;}

  @media (max-width:640px){
    .list{table-layout:auto;}
    th.col-writer,th.col-head,th.col-time,td.c-writer,td.c-head,td.c-time{display:none;}
    .list td.title{white-space:normal; line-height:1.4;}
    .info-box{grid-template-columns:repeat(2,1fr);}
    .info-box div:nth-child(2){border-right:none;}
    .info-box div:nth-child(-n+2){border-bottom:1px solid #e1e1e1;}
    .list td,.list th{font-size:12px;}
    .detail th{width:90px;}
  }
</style>
</head>
<body>
  <div class="topbar"><div class="inner"><a class="logo" href="#">gbsw<span>inside</span></a></div></div>
  <div class="gnb"><div class="inner"><span class="on">갤러리</span><span>마이너갤</span><span>미니갤</span><span>인물갤</span><span>갤로그</span><span>디시트렌드</span></div></div>

  <div class="wrap">
    <div class="gall-head">
      <div class="gall-title">와이파이 끊김 갤러리</div>
    </div>

    <div class="view" id="view" hidden></div>

    <div class="tab-row">
      <div class="tabs">
        <button type="button" id="tab-all" class="on">전체글</button>
        <button type="button" id="tab-best">개념글</button>
      </div>
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

    <table class="list">
      <thead>
        <tr><th class="col-no">번호</th><th class="col-head">말머리</th><th>제목</th><th class="col-writer">글쓴이</th><th class="col-date">날짜</th><th class="col-time">시작</th><th class="col-time">종료</th><th class="col-dur">지속</th></tr>
      </thead>
      <tbody>
        <tr class="notice" id="notice-row">
          <td><span class="tag" id="tag">공지</span></td>
          <td class="title" colspan="7"><span id="status-text">확인 중…</span><span class="sub-detail" id="status-detail"></span></td>
        </tr>
      </tbody>
      <tbody id="ranking-body">
        <tr><td colspan="8" class="empty">기록 불러오는 중…</td></tr>
      </tbody>
    </table>
    <div class="paging" id="paging"></div>

    <div class="footer">
      이 갤러리는 기숙사 와이파이 끊김을 자동으로 기록합니다. 인기순은 오래 끊긴 순입니다.<br>
      Copyright © gbswinside. All rights reserved.
    </div>
  </div>

<script>
const PER_PAGE = 30;
const WEEK = "일월화수목금토";
let outageStart = null;
let status = null;
let stats = null;
let records = [];        // 서버가 준 순서 (오래 끊긴 순, rank 포함)
let byNo = [];           // 오래된 순. 글번호 = 인덱스+1
let sortMode = "pop";    // "pop" = 인기순(오래 끊긴 순), "date" = 날짜순
let dateDesc = true;     // 날짜순일 때 true = 최신순 ▼, false = 오래된순 ▲
let tab = "all";         // "all" = 전체글, "best" = 개념글(1~3위)
let page = 1;

const p2 = n => String(n).padStart(2,"0");

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

function sameDay(a, b){
  return a.getFullYear()===b.getFullYear() && a.getMonth()===b.getMonth() && a.getDate()===b.getDate();
}
function hms(d){ return p2(d.getHours())+":"+p2(d.getMinutes())+":"+p2(d.getSeconds()); }
function ymd(d){ return d.getFullYear()+"."+p2(d.getMonth()+1)+"."+p2(d.getDate()); }
function fullDate(d){ return ymd(d)+" "+hms(d); }
function monthDay(d){ return (d.getMonth()+1)+"월 "+d.getDate()+"일"; }
function headTag(sec){ return sec < 60 ? "찔끔" : sec < 600 ? "터짐" : sec < 3600 ? "대형" : "초대형"; }
function postTitle(r){ return monthDay(r.s) + " 와이파이 터짐"; }
function curNo(){
  const m = location.hash.match(/no=([0-9]+)/);
  return m ? Number(m[1]) : null;
}

function getVote(r){ try{ return localStorage.getItem("vote:"+r.start); }catch(e){ return null; } }
function setVote(r, v){
  try{
    if(getVote(r) === v) localStorage.removeItem("vote:"+r.start);
    else localStorage.setItem("vote:"+r.start, v);
  }catch(e){}
  renderView();
}

async function refreshStatus(){
  try{
    const res = await fetch("/api/status");
    const d = await res.json();
    status = d;
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
      st.textContent = "[속보] " + monthDay(new Date()) + " 와이파이 지금 터짐";
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
    stats = d.stats;
    document.getElementById("c-count").textContent = stats.total_outages + "회";
    document.getElementById("c-total").textContent = stats.total_downtime_human;
    document.getElementById("c-longest").textContent = stats.longest_human;
    document.getElementById("c-avg").textContent = stats.avg_human;

    records = d.ranking.map(r => ({...r, s: new Date(r.start), e: new Date(r.end)}));
    byNo = records.slice().sort((a, b) => a.s - b.s);
    byNo.forEach((r, i) => r.no = i + 1);
    document.getElementById("tab-all").innerHTML = '전체글<span class="cnt">' + records.length + '</span>';
    renderList(); renderView();
  }catch(e){}
}

function renderList(){
  const body = document.getElementById("ranking-body");
  const pager = document.getElementById("paging");
  let list = tab === "best" ? records.filter(r => r.rank <= 3) : records.slice();
  if(list.length === 0){
    body.innerHTML = '<tr><td colspan="8" class="empty">등록된 게시물이 없습니다.</td></tr>';
    pager.innerHTML = "";
    return;
  }
  if(sortMode === "date") list.sort((a, b) => dateDesc ? b.s - a.s : a.s - b.s);
  else list.sort((a, b) => a.rank - b.rank);

  const pages = Math.ceil(list.length / PER_PAGE);
  page = Math.min(page, pages);
  const cur = curNo();
  body.innerHTML = list.slice((page-1)*PER_PAGE, page*PER_PAGE).map(r => {
    const top = r.rank <= 3;
    const cls = (top ? "r"+r.rank : "") + (r.no === cur ? " cur" : "");
    const head = headTag(r.duration_sec);
    return `<tr class="${cls}">
      <td class="c-no">${r.no}</td>
      <td class="c-head${r.duration_sec >= 600 ? " big" : ""}">${head}</td>
      <td class="title"><a href="#no=${r.no}"><span class="ico${top ? " best" : ""}"></span>${top ? '<span class="best">개념</span>' : ""}${postTitle(r)}</a><span class="cmt">[${Math.floor(r.duration_sec/60)}]</span></td>
      <td class="c-writer"><span class="writer">ㅇㅇ</span><span class="ip">(172.28)</span></td>
      <td>${ymd(r.s)}</td>
      <td class="c-time">${hms(r.s)}</td>
      <td class="c-time">${sameDay(r.s, r.e) ? hms(r.e) : fullDate(r.e)}</td>
      <td>${r.duration_human}</td>
    </tr>`;
  }).join("");

  let html = "";
  for(let i = 1; i <= pages; i++) html += `<button type="button" data-p="${i}" class="${i === page ? "on" : ""}">${i}</button>`;
  pager.innerHTML = pages > 1 ? html : "";
}

function renderView(){
  const box = document.getElementById("view");
  const r = byNo[curNo() - 1];
  if(!r || !stats){
    box.hidden = true;
    document.title = "와이파이 끊김 갤러리";
    return;
  }
  box.hidden = false;
  document.title = postTitle(r) + " - 와이파이 끊김 갤러리";

  const day = byNo.filter(x => sameDay(x.s, r.s));
  const nth = day.indexOf(r) + 1;
  const dayTotal = day.reduce((sum, x) => sum + x.duration_sec, 0);
  const prev = byNo[r.no - 2], next = byNo[r.no];
  const isToday = sameDay(r.s, new Date());
  const ratio = stats.avg_sec ? (r.duration_sec / stats.avg_sec).toFixed(1) : "-";
  const topPct = Math.max(1, Math.ceil(r.rank / records.length * 100));
  const vote = getVote(r);
  const up = Math.floor(r.duration_sec / 60) + (vote === "up" ? 1 : 0);
  const down = vote === "down" ? 1 : 0;

  const midnight = new Date(r.s.getFullYear(), r.s.getMonth(), r.s.getDate()).getTime();
  const pos = t => Math.min(100, Math.max(0, (t - midnight) / 864000));
  let quiet = "";
  if(status && status.quiet_hours_enabled){
    const [a, b] = status.quiet_hours_range.split("~").map(x => { const [h, m] = x.split(":"); return (h*60 + Number(m)) / 14.4; });
    quiet = a < b ? `<div class="q" style="left:${a}%;width:${b-a}%"></div>`
                  : `<div class="q" style="left:0;width:${b}%"></div><div class="q" style="left:${a}%;width:${100-a}%"></div>`;
  }
  const segs = day.map(x => {
    const L = pos(x.s.getTime()), W = pos(x.e.getTime()) - L;
    return `<a href="#no=${x.no}" class="${x === r ? "me" : ""}" style="left:${L}%;width:${W}%" title="${hms(x.s)} ~ ${hms(x.e)} (${x.duration_human})"></a>`;
  }).join("");

  box.innerHTML = `
    <div class="view-head">
      <h3 class="view-title"><span class="h">[${headTag(r.duration_sec)}]</span>${postTitle(r)}</h3>
      <div class="view-meta">
        <div><span class="writer">ㅇㅇ</span><span class="ip">(172.28)</span><span class="bar">|</span>${fullDate(r.s)}</div>
        <div>인기 ${r.rank}위<span class="bar">|</span>추천 ${up}<span class="bar">|</span>번호 ${r.no}</div>
      </div>
    </div>
    <div class="view-body">
      <p>${monthDay(r.s)} (${WEEK[r.s.getDay()]}) 와이파이 터짐</p>
      <p><b>${hms(r.s)}</b>부터 <b>${hms(r.e)}</b>까지 <b class="red">${r.duration_human}</b> 동안 인터넷 안 됐음</p>
      <p>${isToday ? "오늘만" : "이날만"} ${nth}번째 터진 거임${day.length > 1 ? ` (${isToday ? "오늘" : "이날"} 총 ${day.length}번)` : ""}</p>

      <table class="detail">
        <tr><th>날짜</th><td>${r.s.getFullYear()}년 ${monthDay(r.s)} (${WEEK[r.s.getDay()]})</td></tr>
        <tr><th>터진 시각</th><td>${hms(r.s)}</td></tr>
        <tr><th>복구 시각</th><td>${sameDay(r.s, r.e) ? hms(r.e) : fullDate(r.e)}</td></tr>
        <tr><th>지속 시간</th><td><b>${r.duration_human}</b></td></tr>
        <tr><th>인기 순위</th><td>${r.rank}위 / 전체 ${records.length}건 <span class="gray">(상위 ${topPct}%)</span></td></tr>
        <tr><th>평균 대비</th><td>평균(${stats.avg_human})의 ${ratio}배</td></tr>
        <tr><th>${isToday ? "오늘" : "이날"} 끊김</th><td>${day.length}회, 합계 ${fmtDuration(dayTotal)}</td></tr>
        <tr><th>직전 끊김</th><td>${prev ? `복구되고 ${fmtDuration((r.s - prev.e) / 1000)} 만에 또 터짐 <span class="gray">(${fullDate(prev.e)} 복구)</span>` : "첫 기록"}</td></tr>
      </table>

      <div class="tl-wrap">
        <div class="tl-label">${monthDay(r.s)} 와이파이 상황 <span class="gray">(빨강 = 끊김, 빗금 = 미감시)</span></div>
        <div class="tl">${quiet}${segs}</div>
        <div class="tl-scale"><span>0시</span><span>6시</span><span>12시</span><span>18시</span><span>24시</span></div>
      </div>
    </div>
    <div class="recom">
      <button type="button" class="up${vote === "up" ? " on" : ""}" id="vote-up"><span class="n">${up}</span>개념 추천</button>
      <button type="button" class="down${vote === "down" ? " on" : ""}" id="vote-down"><span class="n">${down}</span>비추</button>
    </div>
    <div class="view-nav">
      ${next ? `<a href="#no=${next.no}"><span class="k">다음글</span>${postTitle(next)} (${next.duration_human})</a>` : ""}
      ${prev ? `<a href="#no=${prev.no}"><span class="k">이전글</span>${postTitle(prev)} (${prev.duration_human})</a>` : ""}
    </div>
    <div class="view-btns"><a href="#">목록</a></div>`;
  document.getElementById("vote-up").onclick = () => setVote(r, "up");
  document.getElementById("vote-down").onclick = () => setVote(r, "down");
}

function updateButtons(){
  document.getElementById("sort-pop").className = sortMode === "pop" ? "on" : "";
  document.getElementById("sort-date").className = sortMode === "date" ? "on" : "";
  document.getElementById("date-arrow").textContent = dateDesc ? "▼" : "▲";
  document.getElementById("sort-date").title = dateDesc ? "최신순 (누르면 오래된순)" : "오래된순 (누르면 최신순)";
  document.getElementById("tab-all").classList.toggle("on", tab === "all");
  document.getElementById("tab-best").classList.toggle("on", tab === "best");
}

function relist(){ page = 1; updateButtons(); renderList(); }
document.getElementById("sort-pop").onclick = () => { sortMode = "pop"; relist(); };
document.getElementById("sort-date").onclick = () => {
  if(sortMode === "date") dateDesc = !dateDesc;  // 이미 날짜순이면 화살표 방향 전환
  else sortMode = "date";
  relist();
};
document.getElementById("tab-all").onclick = () => { tab = "all"; relist(); };
document.getElementById("tab-best").onclick = () => { tab = "best"; relist(); };
document.getElementById("paging").onclick = e => {
  const p = e.target.dataset.p;
  if(p){ page = Number(p); renderList(); }
};
window.onhashchange = () => {
  renderView(); renderList();
  const box = document.getElementById("view");
  if(box.hidden) window.scrollTo(0, 0); else box.scrollIntoView();
};
updateButtons();

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