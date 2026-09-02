#!/usr/bin/env python3
"""
benchmark.py  —  정량 성능 측정 도구
논문 실험: AI 추론 서버(/api/predict)를 N회 연속 호출하여
지연 시간(ms)·처리량(req/s)을 측정하고 metrics.csv로 저장.

사용법:
    python3 benchmark.py                          # 기본값: 500회, localhost:8080
    python3 benchmark.py --count 1000 --port 8080
    python3 benchmark.py --endpoint /api/predict --output results.csv
"""

import argparse
import csv
import json
import statistics
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime

DEFAULT_HOST     = "localhost"
DEFAULT_PORT     = 8080
DEFAULT_ENDPOINT = "/api/predict"
DEFAULT_COUNT    = 500
DEFAULT_OUTPUT   = "metrics.csv"

SAMPLE_PROMPTS = [
    "이 입력 데이터의 분류 결과를 알려줘",
    "센서 값 0.87, 0.23, 0.95 를 분석해 줘",
    "정상 트래픽 여부를 판단해 줘",
    "패킷 헤더를 분석하고 위험도를 평가해 줘",
    "로그 데이터에서 이상 징후를 탐지해 줘",
]


def make_request(url: str, prompt: str):
    """
    단일 POST 요청을 보내고 (latency_ms, status_code, result_preview)를 반환.
    """
    payload = json.dumps({"prompt": prompt}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read()
            latency_ms = (time.perf_counter() - t0) * 1000
            data = json.loads(body)
            return latency_ms, resp.status, data.get("result", "")[:40]
    except urllib.error.HTTPError as e:
        latency_ms = (time.perf_counter() - t0) * 1000
        return latency_ms, e.code, f"HTTP {e.code}"
    except urllib.error.URLError as e:
        latency_ms = (time.perf_counter() - t0) * 1000
        return latency_ms, 0, f"연결 실패: {e.reason}"


def run_benchmark(url: str, count: int, output_path: str) -> dict:
    print("=" * 65)
    print("  kShield 논문 실험 — AI 추론 성능 벤치마크")
    print("=" * 65)
    print(f"  대상 URL : {url}")
    print(f"  반복 횟수: {count} 회")
    print(f"  출력 파일: {output_path}")
    print("-" * 65)

    latencies   = []
    status_ok   = 0
    status_fail = 0
    rows        = []          # CSV용 행 데이터

    wall_start = time.perf_counter()

    for i in range(count):
        prompt  = SAMPLE_PROMPTS[i % len(SAMPLE_PROMPTS)]
        lat, code, preview = make_request(url, prompt)

        latencies.append(lat)
        rows.append({
            "seq":        i + 1,
            "latency_ms": round(lat, 3),
            "status":     code,
            "prompt_idx": i % len(SAMPLE_PROMPTS),
        })

        if code == 200:
            status_ok += 1
        else:
            status_fail += 1

        if (i + 1) % 100 == 0 or i == 0:
            avg_so_far = statistics.mean(latencies)
            print(f"  [{i+1:>5}/{count}]  avg={avg_so_far:.2f} ms  ok={status_ok}  fail={status_fail}")

    wall_elapsed = time.perf_counter() - wall_start

    # ── 통계 계산 ─────────────────────────────────────────────────
    sorted_lat = sorted(latencies)
    n          = len(latencies)

    def percentile(lst, p):
        idx = max(0, int(len(lst) * p / 100) - 1)
        return lst[idx]

    stats = {
        "timestamp":      datetime.now().isoformat(timespec="seconds"),
        "url":            url,
        "total_requests": count,
        "success":        status_ok,
        "failure":        status_fail,
        "success_rate_%": round(status_ok / count * 100, 2),
        "total_time_s":   round(wall_elapsed, 3),
        "throughput_rps": round(count / wall_elapsed, 2),
        "latency_mean_ms":   round(statistics.mean(latencies), 3),
        "latency_median_ms": round(statistics.median(latencies), 3),
        "latency_stdev_ms":  round(statistics.stdev(latencies) if n > 1 else 0, 3),
        "latency_min_ms":    round(sorted_lat[0], 3),
        "latency_max_ms":    round(sorted_lat[-1], 3),
        "latency_p50_ms":    round(percentile(sorted_lat, 50), 3),
        "latency_p95_ms":    round(percentile(sorted_lat, 95), 3),
        "latency_p99_ms":    round(percentile(sorted_lat, 99), 3),
    }

    # ── CSV 저장 ────────────────────────────────────────────────────
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        # 섹션 1: 요약 통계
        writer = csv.writer(f)
        writer.writerow(["## Summary Statistics"])
        for k, v in stats.items():
            writer.writerow([k, v])
        writer.writerow([])

        # 섹션 2: 요청별 원시 데이터
        writer.writerow(["## Per-Request Data"])
        dict_writer = csv.DictWriter(f, fieldnames=["seq", "latency_ms", "status", "prompt_idx"])
        dict_writer.writeheader()
        dict_writer.writerows(rows)

    # ── 콘솔 출력 ───────────────────────────────────────────────────
    print()
    print("=" * 65)
    print("  결과 요약")
    print("=" * 65)
    print(f"  총 요청 수     : {count}")
    print(f"  성공 / 실패    : {status_ok} / {status_fail}  ({stats['success_rate_%']}%)")
    print(f"  총 소요 시간   : {stats['total_time_s']} s")
    print(f"  처리량         : {stats['throughput_rps']} req/s")
    print(f"  평균 지연 시간 : {stats['latency_mean_ms']} ms")
    print(f"  중앙값 지연    : {stats['latency_median_ms']} ms")
    print(f"  표준편차       : {stats['latency_stdev_ms']} ms")
    print(f"  최솟값 / 최댓값: {stats['latency_min_ms']} / {stats['latency_max_ms']} ms")
    print(f"  P50 / P95 / P99: {stats['latency_p50_ms']} / {stats['latency_p95_ms']} / {stats['latency_p99_ms']} ms")
    print(f"  저장 파일      : {output_path}")
    print("=" * 65)

    return stats


def main():
    parser = argparse.ArgumentParser(description="AI 추론 서버 성능 벤치마크")
    parser.add_argument("--host",     default=DEFAULT_HOST,     help="서버 호스트 (기본: localhost)")
    parser.add_argument("--port",     type=int, default=DEFAULT_PORT, help="서버 포트 (기본: 8080)")
    parser.add_argument("--endpoint", default=DEFAULT_ENDPOINT, help="API 엔드포인트 (기본: /api/predict)")
    parser.add_argument("--count",    type=int, default=DEFAULT_COUNT, help="반복 호출 횟수 (기본: 500)")
    parser.add_argument("--output",   default=DEFAULT_OUTPUT,   help="CSV 출력 경로 (기본: metrics.csv)")
    args = parser.parse_args()

    url = f"http://{args.host}:{args.port}{args.endpoint}"

    # 서버 연결 확인
    try:
        health_url = f"http://{args.host}:{args.port}/health"
        with urllib.request.urlopen(health_url, timeout=5) as r:
            info = json.loads(r.read())
        print(f"서버 연결 확인: {info.get('status')}  모델={info.get('model')}")
    except Exception as e:
        print(f"[오류] 서버에 연결할 수 없습니다: {e}", file=sys.stderr)
        print("  →  ai_server.py 를 먼저 실행하세요.", file=sys.stderr)
        sys.exit(1)

    run_benchmark(url, args.count, args.output)


if __name__ == "__main__":
    main()
