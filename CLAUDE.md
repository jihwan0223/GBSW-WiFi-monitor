# GBSW 와이파이 끊김 감시 프로젝트 — 인수인계

## 한 줄 요약
기숙사 와이파이(`gbsw314`)가 끊긴 시간을 기록해서, 오래 끊긴 순으로 랭킹을 보여주는 웹사이트.
공개 주소: **https://wifi.gbsw.store** (디시인사이드 갤러리 스타일 디자인)

## 사용자 정보
- 학생. 터미널(CLI)이 익숙하지 않음 → 명령어는 한 줄씩, 어느 터미널 창에서 칠지까지 알려줄 것.
- 한국어로 대화. 설명 없는 쓸데없는 주석 싫어함. README 필요 없음.
- 코드를 바꾸기 전에 무엇을 할지 먼저 말해주길 원함.

## 구조
```
[기숙사 여분 맥북 (항상 켜둠, 와이파이 gbsw314)]
  ├─ wifi_monitor.py  ← 3초마다 연결 확인 + 웹서버 (127.0.0.1:8765)
  └─ cloudflared      ← Cloudflare Tunnel로 wifi.gbsw.store 에 공개
```
- Python 표준 라이브러리만 사용 (pip 설치 없음). Python 3.13 (python.org 설치판).
- 파일 위치: `/Users/jungjihwan/GBSW-WiFi-monitor/`
  - `wifi_monitor.py` — 감시 + 웹서버 + HTML 전부 들어있는 단일 파일
  - `config.json` — 설정
  - `wifi_outages.json` — 끊김 기록 (지우면 기록 초기화)
  - `wifi_monitor.log` — 실행 로그

## config.json (현재)
```json
{
  "gateway": "auto",
  "target_ssid": "",
  "interval_sec": 3,
  "quiet_hours_enabled": true,
  "quiet_hours_start": "01:00",
  "quiet_hours_end": "06:05"
}
```
- `target_ssid`는 일부러 비워둠: macOS 14.4+ 에서 SSID 조회가 불안정해서 오탐 발생 → 끔.
- 01:00~06:05는 학교 와이파이가 원래 꺼지는 시간이라 기록 안 함 (미감시).

## wifi_monitor.py 핵심 동작
- 연결 판단: `ping_once(게이트웨이) or check_internet()`
  - 학교 네트워크(게이트웨이 `172.28.0.254`)가 ICMP ping을 막음 → ping 실패 시
    `1.1.1.1:53`, `8.8.8.8:53` TCP 연결로 한 번 더 확인 (이걸로 오탐 해결함).
- 2번 연속 실패해야 "끊김" 처리 (`FAILS_TO_MARK_DISCONNECTED = 2`).
- 끊긴 상태로 재시작돼도 `wifi_outages.json`의 `ongoing`으로 이어서 기록.
- 미감시 시간대에 들어가면 진행 중이던 끊김은 그 시점에 마감.
- API: `/api/status`, `/api/history` (JSON). `/`는 HTML 대시보드.
- 화면: 디시 갤러리 스타일. 상단 공지 줄에 현재 상태(속보/정상/야간),
  목록 오른쪽 위 **인기순**(오래 끊긴 순) / **날짜순 ▼▲**(누를 때마다 최신↔오래된) 정렬 버튼.
  정렬은 브라우저에서만 처리 (서버 API는 변경 없음). 1~3위에 `개념` 딱지.

## 자동 실행 (맥)
1. **wifi_monitor.py** — 사용자 LaunchAgent
   - `~/Library/LaunchAgents/com.gbsw.wifimonitor.plist` (RunAtLoad, KeepAlive)
   - 실행 파일: `/Library/Frameworks/Python.framework/Versions/3.13/Resources/Python.app/Contents/MacOS/Python`
   - 상태 확인: `launchctl list | grep gbsw` → 첫 칸에 숫자(PID)면 실행 중
2. **cloudflared** — 시스템 LaunchDaemon (`sudo cloudflared service install <토큰>` 으로 설치)
   - 상태 확인: `sudo launchctl list | grep cloudflare` → `com.cloudflare.cloudflared` 보이면 정상
   - (sudo 없이 보면 Cloudflare WARP 앱만 보여서 헷갈림)

## 코드 수정 후 적용하는 법
```
mv ~/Downloads/wifi_monitor.py ~/GBSW-WiFi-monitor/wifi_monitor.py
launchctl kickstart -k gui/$(id -u)/com.gbsw.wifimonitor
launchctl list | grep gbsw
```
- `launchctl unload` / `bootstrap`은 `5: Input/output error`가 자주 나서 **kickstart -k** 사용.
- 다운로드한 파일 이름이 `Wifi monitor.py`, `Config.json`처럼 바뀌는 일이 잦음 → `ls`로 먼저 확인.
- 기록 초기화: `rm ~/GBSW-WiFi-monitor/wifi_outages.json` 후 kickstart.

## Cloudflare 설정
- 도메인 `gbsw.store` → Cloudflare 네임서버로 연결 완료.
- 터널: 대시보드에서 만든 원격 관리형 터널 (이름 `WiFi-gbsw`), 새 대시보드 "Networking > Tunnels".
- 라우트: "+ Add route" → Published application → `wifi.gbsw.store` → **`http://127.0.0.1:8765`**
  (`http://` 빼면 형식 오류, `localhost` 대신 `127.0.0.1` 써야 502 안 남)

## 자주 겪은 에러
| 증상 | 원인 / 해결 |
|---|---|
| 1033 에러 | cloudflared가 안 돌고 있음 → `sudo launchctl list \| grep cloudflare` 확인, 필요하면 대시보드에서 토큰 Rotate 후 재설치 |
| 502 Bad Gateway | wifi_monitor.py가 꺼져 있거나 라우트 URL 오류 |
| Address already in use | 서버가 이미 하나 떠 있음 → `pkill -f wifi_monitor.py` |
| 와이파이 되는데 "끊김" | ICMP 차단 (check_internet으로 해결됨) / SSID 오탐 (target_ssid 비움) |
| 터미널이 먹통 | 서버가 앞에서 돌고 있는 탭에 입력 중 → Cmd+T로 새 탭 |

## 확인 안 된 것 / 다음 할 일
- [ ] 마지막 업데이트(인기순/날짜순 정렬)가 사이트에 반영됐는지 확인
      (`kickstart -k` 후 PID 20589로 실행 중인 것까지 확인함. `grep -c sort-pop ~/GBSW-WiFi-monitor/wifi_monitor.py` 가 1 이상이면 새 파일)
- [ ] `quiet_hours_end: "06:01"` 반영 및 기록 삭제가 실제로 됐는지 확인
