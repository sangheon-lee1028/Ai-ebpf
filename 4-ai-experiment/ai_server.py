#!/usr/bin/env python3
"""
ai_server.py  —  Group 1: L7 Application-Layer Defense
논문 실험 대조군 1: L7 계층 방어(키워드 필터 + 속도 제한)가 적용된 AI 추론 서버

실행 방법:
    python3 ai_server.py
    (모델 파일 경로를 바꾸려면: python3 ai_server.py --model /your/path/model.bin)

의존성: 표준 라이브러리만 사용 (PyTorch/Flask 불필요)
"""

import os
import re
import sys
import json
import time
import hashlib
import logging
import argparse
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
from collections import defaultdict

# ── 설정 ──────────────────────────────────────────────────────────
DEFAULT_MODEL_PATH = "/opt/models/model.bin"
DEFAULT_MODEL_DIR  = "/opt/models"
SERVER_HOST        = "0.0.0.0"
SERVER_PORT        = 8080

# ── llm-guard 통합 (ProtectAI) ──────────────────────────────────────
# pip install llm-guard 로 설치 시 ML 스캐너 자동 활성화.
# 미설치 시 아래 정규식 기반 fallback으로 투명하게 전환.
try:
    from llm_guard.input_scanners import PromptInjection
    from llm_guard.input_scanners.prompt_injection import MatchType
    _LLM_GUARD_SCANNER = PromptInjection(threshold=0.75, match_type=MatchType.FULL)
    DEFENSE_MODE = "llm-guard (ProtectAI ML)"
except ImportError:
    _LLM_GUARD_SCANNER = None
    DEFENSE_MODE = "regex-heuristic (fallback)"

# ── 정규식 Fallback — 6개 카테고리 프롬프트 인젝션 탐지 패턴 ────────
# llm-guard 미설치 환경 또는 스캐너 오류 시 사용.
# 각 항목: (컴파일된 패턴, 탐지 레이블)
_INJECTION_PATTERNS: list = [
    # 1. 지시 무효화 (Instruction Override)
    (re.compile(
        r'\b(ignore|disregard|forget|override|bypass)\s+'
        r'(previous|prior|above|all|any)\s+'
        r'(instructions?|prompt|rules?|constraints?|guidelines?)',
        re.I), "지시 무효화 시도"),
    (re.compile(
        r'\b(do not|don\'t|stop)\s+(follow|obey|adhere to)\s+'
        r'(the\s+)?(instructions?|rules?|guidelines?|constraints?)',
        re.I), "규칙 무시 시도"),
    (re.compile(r'new\s+(instruction|directive|command|rule|prompt)\s*[:：]', re.I),
        "새 지시 삽입 시도"),

    # 2. 역할 전환 / 탈옥 (Jailbreak)
    (re.compile(
        r'\b(act|pretend|behave|roleplay|play)\s+(as|like|the role of|you are)\b',
        re.I), "역할 전환 시도"),
    (re.compile(
        r'\byou\s+(are\s+)?(now\s+)?(a|an|the)\s+\w+\s*'
        r'(without\s+restrictions?|with\s+no\s+limits?)?',
        re.I), "페르소나 교체 시도"),
    (re.compile(
        r'\b(DAN|STAN|AIM|Developer\s+Mode|jailbreak|'
        r'unrestricted\s+AI|no[\s\-]filter)\b',
        re.I), "알려진 탈옥 패턴"),
    (re.compile(
        r'(do\s+anything\s+now|without\s+(restrictions?|limits?|constraints?|censorship))',
        re.I), "무제한 모드 요청"),

    # 3. 시스템 프롬프트 / 모델 추출 (Exfiltration)
    (re.compile(
        r'\b(reveal|show|display|print|output|dump|expose)\s+'
        r'(your\s+)?(system\s+prompt|instructions?|model\s+weights?|'
        r'training\s+data|configuration)',
        re.I), "시스템 프롬프트 추출 시도"),
    (re.compile(
        r'(exfiltrate|extract|steal|copy|clone)\s+(the\s+)?(model|weights?|data|file)',
        re.I), "모델 탈취 시도"),
    (re.compile(
        r'what\s+(are|is)\s+your\s+(instructions?|system\s+prompt|initial\s+prompt)',
        re.I), "초기 지시 조회 시도"),

    # 4. 파일 / 경로 접근 (Path Traversal)
    (re.compile(r'(read|open|cat|load|import|include)\s+["\']?(/[a-z]|\.\.\/)', re.I),
        "파일 경로 접근 시도"),
    (re.compile(r'\.\./|/etc/(passwd|shadow|sudoers)|/proc/|/sys/|/opt/models', re.I),
        "민감 경로 접근 시도"),
    (re.compile(r'\b(model\.bin|weights\.gguf|tokenizer\.json|vocab\.txt)\b', re.I),
        "AI 모델 파일 직접 접근 시도"),

    # 5. 코드 / 쉘 인젝션 (Code Injection)
    (re.compile(
        r'\b(os\.(system|popen|execv?|listdir)|subprocess\.|'
        r'eval\s*\(|exec\s*\(|__import__\s*\()',
        re.I), "코드 인젝션 시도"),
    (re.compile(r'`[^`]{1,200}`|\$\([^)]{1,200}\)', re.I),
        "쉘 명령 치환 시도"),

    # 6. 프롬프트 구분자 인젝션 (Delimiter Injection)
    (re.compile(
        r'(###\s*system|<\|system\|>|<\|im_start\|>|<\|im_end\|>|'
        r'\[INST\]|\[\/INST\]|<<SYS>>|</s>)',
        re.I), "프롬프트 구분자 인젝션"),
    (re.compile(r'(human:|assistant:|user:|ai:|bot:)\s*\n', re.I),
        "역할 구분자 삽입 시도"),
]

# 속도 제한: IP당 10초 창에 최대 20 요청
RATE_LIMIT_WINDOW = 10
RATE_LIMIT_MAX    = 20

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("ai_server")

# ── 모델 시뮬레이션 ───────────────────────────────────────────────
MODEL_PATH = DEFAULT_MODEL_PATH   # main()에서 인자로 덮어씀

MOCK_MODEL_SIZE_MB = 16

def create_mock_model(path):
    """논문 실험용 가상 모델 바이너리를 생성한다."""
    model_dir = os.path.dirname(path)
    try:
        os.makedirs(model_dir, exist_ok=True)
    except PermissionError:
        log.error(f"디렉토리 생성 권한 없음: {model_dir}  →  sudo python3 ai_server.py 로 실행하거나 경로를 변경하세요.")
        sys.exit(1)

    if os.path.exists(path):
        size_mb = os.path.getsize(path) / 1024 / 1024
        log.info(f"기존 모델 파일 사용: {path}  ({size_mb:.1f} MB)")
        return

    log.info(f"가상 모델 생성 중: {path}  ({MOCK_MODEL_SIZE_MB} MB) ...")
    import random
    random.seed(42)
    chunk = bytes([random.randint(0, 255) for _ in range(4096)])
    with open(path, "wb") as f:
        f.write(b"AIMODEL\x00")                          # 8-byte 매직 헤더
        for _ in range(MOCK_MODEL_SIZE_MB * 256):        # 4096 B × 4096 = 16 MB
            f.write(chunk)
    os.chmod(path, 0o640)
    log.info(f"모델 생성 완료: {os.path.getsize(path) / 1024 / 1024:.1f} MB  (owner:rw, group:r)")


def load_model(path):
    """
    모델 파일의 헤더를 검증하고 모델 핸들을 반환한다.
    실제 PyTorch 환경에서는 torch.load() 로 교체 가능.
    """
    with open(path, "rb") as f:
        header = f.read(8)
    if header != b"AIMODEL\x00":
        raise ValueError(f"유효하지 않은 모델 형식: {path}")
    size_mb = os.path.getsize(path) / 1024 / 1024
    log.info(f"모델 로드 완료 (헤더 검증 OK)  —  {size_mb:.1f} MB")
    return {"path": path, "size": os.path.getsize(path)}


def run_inference(model_handle, prompt):
    """
    추론을 시뮬레이션한다.
    실제 환경에서는 모델을 GPU에 올려 forward-pass를 수행.
    """
    h = hashlib.sha256(f"{prompt}{model_handle['size']}".encode()).hexdigest()[:8]
    templates = [
        "분석 완료. 분류 결과: 클래스 A (신뢰도 91.2%)",
        "입력 처리 완료. 예측값: 양성 (확률 0.874)",
        "추론 결과: 패턴 매칭 성공 — 정상 트래픽",
        "생성 완료: 요청하신 내용에 대한 응답입니다.",
    ]
    return templates[int(h, 16) % len(templates)]


# ── L7 방어 로직 ──────────────────────────────────────────────────
_rate_store: dict = defaultdict(list)
_rate_lock  = threading.Lock()


def check_rate_limit(ip: str) -> bool:
    now = time.time()
    with _rate_lock:
        _rate_store[ip] = [t for t in _rate_store[ip] if now - t < RATE_LIMIT_WINDOW]
        if len(_rate_store[ip]) >= RATE_LIMIT_MAX:
            return False
        _rate_store[ip].append(now)
    return True


def l7_keyword_filter(text: str):
    """
    L7 프롬프트 인젝션 방어 스캐너.
    반환: (허용 여부: bool, 거부 사유: str)

    우선순위:
      1. llm-guard PromptInjection ML 스캐너 (설치된 경우)
      2. 정규식 6-카테고리 Heuristic (fallback)
    """
    if not L7_DEFENSE_ENABLED:
        return True, ""

    if len(text) > 1000:
        return False, "프롬프트 최대 길이 초과 (1000자)"

    # ── llm-guard ML 스캐너 ─────────────────────────────────────────
    if _LLM_GUARD_SCANNER is not None:
        try:
            _sanitized, is_valid, risk_score = _LLM_GUARD_SCANNER.scan(text)
            if not is_valid:
                return False, f"llm-guard: 프롬프트 인젝션 탐지 (위험도={risk_score:.2f})"
            return True, ""
        except Exception as exc:
            log.warning(f"llm-guard 스캔 오류 ({exc}), regex fallback 사용")

    # ── 정규식 Heuristic fallback ────────────────────────────────────
    for pattern, label in _INJECTION_PATTERNS:
        m = pattern.search(text)
        if m:
            return False, f"{label}: '{m.group()[:50]}'"

    return True, ""


# ── HTTP 핸들러 ────────────────────────────────────────────────────
_model_handle = None   # 서버 시작 시 설정


class AIServerHandler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        log.info(f"{self.address_string()}  {fmt % args}")

    def _send_json(self, code: int, obj: dict):
        body = json.dumps(obj, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)
        return json.loads(raw) if raw else {}

    # ── GET ──────────────────────────────────────────────────────
    def do_GET(self):
        if self.path == "/health":
            self._send_json(200, {
                "status":    "ok",
                "model":     _model_handle["path"],
                "size_mb":   round(_model_handle["size"] / 1024 / 1024, 1),
                "defense":   ["L7 keyword filter", "rate limiting (20 req/10s)"],
                "endpoints": ["/api/predict (filtered)", "/api/v2/predict (unfiltered - VULN)"],
            })
        else:
            self._send_json(404, {"error": "Not found"})

    # ── POST ─────────────────────────────────────────────────────
    def do_POST(self):
        try:
            body = self._read_body()
        except (json.JSONDecodeError, ValueError):
            self._send_json(400, {"error": "요청 본문이 유효한 JSON이 아닙니다"})
            return

        path = urlparse(self.path).path

        # ── /api/predict — L7 방어 적용 (정상 프로덕션 엔드포인트) ──
        if path == "/api/predict":
            ip = self.client_address[0]

            if not check_rate_limit(ip):
                log.warning(f"[L7-RATELIMIT]  {ip}")
                self._send_json(429, {"error": "속도 제한 초과 — 잠시 후 재시도하세요"})
                return

            prompt = body.get("prompt", "")
            allowed, reason = l7_keyword_filter(prompt)

            if not allowed:
                log.warning(f"[L7-BLOCKED]  ip={ip}  reason='{reason}'  prompt='{prompt[:80]}'")
                self._send_json(403, {
                    "error":  "보안 필터에 의해 요청이 차단되었습니다",
                    "reason": reason,
                })
                return

            log.info(f"[L7-ALLOWED]  추론 실행  prompt='{prompt[:60]}'")
            result = run_inference(_model_handle, prompt)
            self._send_json(200, {"result": result, "model": "demo-v1", "defense": "L7-filtered"})
            return

        # ── /api/v2/predict — 필터 미적용 취약 엔드포인트 ────────────
        # 실제 환경에서 개발자가 테스트용으로 남겨두고 잊어버린 엔드포인트를 시뮬레이션.
        # L7 키워드 필터가 전혀 적용되지 않으며, context_file 파라미터로 임의 파일을 열 수 있음.
        elif path == "/api/v2/predict":
            prompt      = body.get("prompt", "")
            target_file = body.get("context_file", "")

            log.info(f"[V2-UNFILTERED]  prompt='{prompt[:60]}'  context_file='{target_file}'")

            if target_file:
                # ▼ 취약점: 경로 검증 없이 임의 파일을 열어 읽음 → eBPF EVIL_OPEN 탐지 포인트
                log.warning(f"[VULN]  context_file 파일 읽기 시도: {target_file}")
                try:
                    with open(target_file, "rb") as f:
                        preview = f.read(256)
                    self._send_json(200, {
                        "result":  f"파일 미리보기(256B hex): {preview[:64].hex()}...",
                        "warning": "필터링되지 않은 DEBUG 엔드포인트 — 실 서비스 사용 금지",
                    })
                    return
                except PermissionError:
                    self._send_json(403, {"error": "파일 접근 권한 없음 (eBPF에 의해 차단되었을 수 있음)"})
                    return
                except FileNotFoundError:
                    self._send_json(404, {"error": f"파일 없음: {target_file}"})
                    return

            result = run_inference(_model_handle, prompt)
            self._send_json(200, {
                "result":  result,
                "warning": "필터링되지 않은 엔드포인트입니다",
            })
            return

        else:
            self._send_json(404, {"error": "Not found"})


# ── 진입점 ────────────────────────────────────────────────────────
L7_DEFENSE_ENABLED = True

def main():
    global _model_handle, MODEL_PATH, L7_DEFENSE_ENABLED

    parser = argparse.ArgumentParser(description="AI 추론 서버 (논문 실험)")
    parser.add_argument("--model",  default=DEFAULT_MODEL_PATH, help="모델 파일 경로")
    parser.add_argument("--port",   type=int, default=SERVER_PORT, help="서버 포트 (기본: 8080)")
    parser.add_argument("--no-l7",  action="store_true", help="L7 방어 비활성화 (Group 2 실험용)")
    args = parser.parse_args()
    MODEL_PATH = args.model
    L7_DEFENSE_ENABLED = not args.no_l7

    group = "Group 2: eBPF-only" if args.no_l7 else "Group 1/3: L7 Application-Layer Defense"
    print("=" * 65)
    print(f"  AI Inference Server  —  {group}")
    print("=" * 65)
    log.info(f"L7 방어: {'비활성화 (--no-l7)' if args.no_l7 else DEFENSE_MODE}")

    create_mock_model(MODEL_PATH)
    _model_handle = load_model(MODEL_PATH)

    server = HTTPServer((SERVER_HOST, args.port), AIServerHandler)

    log.info(f"서버 시작: http://{SERVER_HOST}:{args.port}")
    log.info("엔드포인트:")
    log.info("  GET  /health                     — 상태 확인")
    log.info("  POST /api/predict                — [L7 방어 적용] 프로덕션 추론")
    log.info("  POST /api/v2/predict             — [취약] 필터 없는 DEBUG 엔드포인트")
    log.info("Ctrl-C 로 종료")
    print("-" * 65)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("서버 종료.")


if __name__ == "__main__":
    main()
