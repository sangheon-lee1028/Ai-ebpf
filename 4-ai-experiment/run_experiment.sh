#!/usr/bin/env bash
# run_experiment.sh  —  논문 실험 자동화 스크립트
#
# 실행 순서:
#   1. AI 추론 서버(ai_server.py) 구동
#   2. kShield eBPF 모듈 백그라운드 실행
#   3. attack.py  — L7 우회 + EVIL_OPEN 공격 시뮬레이션
#   4. benchmark.py — 정량 성능 측정 (metrics.csv 생성)
#   5. 종료 시 모든 백그라운드 프로세스 정리
#
# 사용법:
#   chmod +x run_experiment.sh
#   sudo ./run_experiment.sh                          # 기본값으로 실행
#   sudo ./run_experiment.sh --skip-ebpf              # kShield 제외 (Group 1 측정)
#   sudo ./run_experiment.sh --attack-count 50        # 공격 횟수 지정
#   sudo ./run_experiment.sh --bench-count 1000       # 벤치마크 횟수 지정

set -euo pipefail

# ── 경로 설정 (환경에 따라 수정) ──────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
KSHIELD_BIN="${PROJECT_ROOT}/3-source-code/v0.01/src/libbpf-bootstrap/kprobe"
AI_SERVER="${SCRIPT_DIR}/ai_server.py"
ATTACK_SCRIPT="${SCRIPT_DIR}/attack.py"
BENCH_SCRIPT="${SCRIPT_DIR}/benchmark.py"

MODEL_PATH="/opt/models/model.bin"
SERVER_HOST="localhost"
SERVER_PORT=8080

# ── 실험 파라미터 ─────────────────────────────────────────────────────
ATTACK_COUNT=30          # 공격 스크립트 반복 횟수
BENCH_COUNT=500          # 벤치마크 반복 횟수
KSHIELD_EVENT=2          # eBPF 이벤트 번호 (2 = EVIL_OPEN)
SKIP_EBPF=false

RESULTS_DIR="${SCRIPT_DIR}/results"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
OUTPUT_CSV="${RESULTS_DIR}/metrics_${TIMESTAMP}.csv"
LOG_SERVER="${RESULTS_DIR}/server_${TIMESTAMP}.log"
LOG_KSHIELD="${RESULTS_DIR}/kshield_${TIMESTAMP}.log"
LOG_ATTACK="${RESULTS_DIR}/attack_${TIMESTAMP}.log"

# ── PID 추적 (cleanup에서 사용) ──────────────────────────────────────
SERVER_PID=""
KSHIELD_PID=""

# ── 색상 출력 ────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

log_info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
log_ok()      { echo -e "${GREEN}[OK]${RESET}    $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${RESET}   $*"; }
log_error()   { echo -e "${RED}[ERROR]${RESET}  $*"; }
log_section() { echo -e "\n${BOLD}━━━  $*  ━━━${RESET}"; }

# ── 인자 파싱 ────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-ebpf)    SKIP_EBPF=true; shift ;;
        --attack-count) ATTACK_COUNT="$2"; shift 2 ;;
        --bench-count)  BENCH_COUNT="$2"; shift 2 ;;
        --model)        MODEL_PATH="$2"; shift 2 ;;
        --port)         SERVER_PORT="$2"; shift 2 ;;
        *) log_error "알 수 없는 옵션: $1"; exit 1 ;;
    esac
done

# ── 종료 시 정리 함수 ────────────────────────────────────────────────
cleanup() {
    log_section "프로세스 정리"

    if [[ -n "${KSHIELD_PID}" ]] && kill -0 "${KSHIELD_PID}" 2>/dev/null; then
        log_info "kShield 종료 (PID ${KSHIELD_PID})"
        kill "${KSHIELD_PID}" 2>/dev/null || true
        wait "${KSHIELD_PID}" 2>/dev/null || true
        log_ok "kShield 종료 완료"
    fi

    if [[ -n "${SERVER_PID}" ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
        log_info "AI 서버 종료 (PID ${SERVER_PID})"
        kill "${SERVER_PID}" 2>/dev/null || true
        wait "${SERVER_PID}" 2>/dev/null || true
        log_ok "AI 서버 종료 완료"
    fi

    log_info "로그 파일 위치: ${RESULTS_DIR}/"
    echo -e "${GREEN}실험 종료.${RESET}"
}
trap cleanup EXIT INT TERM

# ── 사전 검사 ────────────────────────────────────────────────────────
log_section "사전 조건 확인"

mkdir -p "${RESULTS_DIR}"

if [[ "${EUID}" -ne 0 ]]; then
    log_error "root 권한 필요: sudo ./run_experiment.sh"
    exit 1
fi

for f in "${AI_SERVER}" "${ATTACK_SCRIPT}" "${BENCH_SCRIPT}"; do
    if [[ ! -f "$f" ]]; then
        log_error "파일 없음: $f"
        exit 1
    fi
done

if [[ "${SKIP_EBPF}" == "false" ]] && [[ ! -x "${KSHIELD_BIN}" ]]; then
    log_error "kShield 바이너리 없음 또는 실행 불가: ${KSHIELD_BIN}"
    log_error "  →  make 를 먼저 실행하거나 --skip-ebpf 옵션을 사용하세요."
    exit 1
fi

log_ok "사전 조건 확인 완료"

# ── STEP 1: AI 서버 구동 ─────────────────────────────────────────────
log_section "STEP 1 / AI 추론 서버 구동"

python3 "${AI_SERVER}" --model "${MODEL_PATH}" --port "${SERVER_PORT}" \
    > "${LOG_SERVER}" 2>&1 &
SERVER_PID=$!
log_info "AI 서버 시작 (PID ${SERVER_PID})  로그: ${LOG_SERVER}"

# 서버 준비 대기 (최대 15초)
READY=false
for i in $(seq 1 15); do
    if curl -sf "http://${SERVER_HOST}:${SERVER_PORT}/health" > /dev/null 2>&1; then
        READY=true
        break
    fi
    sleep 1
done

if [[ "${READY}" == "false" ]]; then
    log_error "서버가 15초 내에 응답하지 않습니다. 로그를 확인하세요: ${LOG_SERVER}"
    exit 1
fi
log_ok "AI 서버 준비 완료 (http://${SERVER_HOST}:${SERVER_PORT})"

# ── STEP 2: kShield 구동 ─────────────────────────────────────────────
log_section "STEP 2 / kShield eBPF 모듈 구동"

if [[ "${SKIP_EBPF}" == "true" ]]; then
    log_warn "kShield 건너뜀 (--skip-ebpf)"
else
    "${KSHIELD_BIN}" -e "${KSHIELD_EVENT}" \
        > "${LOG_KSHIELD}" 2>&1 &
    KSHIELD_PID=$!
    log_info "kShield 시작 (PID ${KSHIELD_PID}  이벤트=${KSHIELD_EVENT})  로그: ${LOG_KSHIELD}"
    sleep 2   # BPF 맵 초기화 대기
    if ! kill -0 "${KSHIELD_PID}" 2>/dev/null; then
        log_error "kShield가 즉시 종료되었습니다. 로그를 확인하세요: ${LOG_KSHIELD}"
        exit 1
    fi
    log_ok "kShield 실행 중"
fi

# ── STEP 3: 공격 스크립트 실행 ──────────────────────────────────────
log_section "STEP 3 / 공격 시뮬레이션 (attack.py)"

log_info "Phase 1: L7 키워드 공격 (차단 예상)"
python3 "${ATTACK_SCRIPT}" --phase 1 --count 5 \
    --server "http://${SERVER_HOST}:${SERVER_PORT}" \
    --model "${MODEL_PATH}" --no-server 2>&1 | tee -a "${LOG_ATTACK}"

log_info "Phase 2: L7 우회 공격 (취약 엔드포인트 접근)"
python3 "${ATTACK_SCRIPT}" --phase 2 --count 5 \
    --server "http://${SERVER_HOST}:${SERVER_PORT}" \
    --model "${MODEL_PATH}" --no-server 2>&1 | tee -a "${LOG_ATTACK}"

log_info "Phase 3: 직접 파일 반복 읽기"
python3 "${ATTACK_SCRIPT}" --phase 3 --count "${ATTACK_COUNT}" \
    --server "http://${SERVER_HOST}:${SERVER_PORT}" \
    --model "${MODEL_PATH}" --no-server 2>&1 | tee -a "${LOG_ATTACK}"

log_info "Phase 4: 고속 open() 연속 호출 (EVIL_OPEN 탐지 유도)"
python3 "${ATTACK_SCRIPT}" --phase 4 --count "${ATTACK_COUNT}" \
    --server "http://${SERVER_HOST}:${SERVER_PORT}" \
    --model "${MODEL_PATH}" --no-server 2>&1 | tee -a "${LOG_ATTACK}"

log_ok "공격 시뮬레이션 완료  로그: ${LOG_ATTACK}"

if [[ "${SKIP_EBPF}" == "false" ]]; then
    log_info "kShield 로그 미리보기:"
    tail -20 "${LOG_KSHIELD}" || true
fi

# ── STEP 4: 성능 벤치마크 ───────────────────────────────────────────
log_section "STEP 4 / 성능 벤치마크 (benchmark.py)"

python3 "${BENCH_SCRIPT}" \
    --host "${SERVER_HOST}" \
    --port "${SERVER_PORT}" \
    --count "${BENCH_COUNT}" \
    --output "${OUTPUT_CSV}"

log_ok "벤치마크 완료  결과: ${OUTPUT_CSV}"

# ── 최종 요약 ─────────────────────────────────────────────────────────
log_section "실험 완료"
echo -e "  ${BOLD}결과 파일:${RESET}"
echo    "    CSV   : ${OUTPUT_CSV}"
echo    "    서버  : ${LOG_SERVER}"
[[ "${SKIP_EBPF}" == "false" ]] && echo "    kShield: ${LOG_KSHIELD}"
echo    "    공격  : ${LOG_ATTACK}"
echo
echo -e "  ${BOLD}논문 수치 확인:${RESET}  cat \"${OUTPUT_CSV}\" | head -20"
