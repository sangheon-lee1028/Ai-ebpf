# eBPF 기반 커널 수준 AI 모델 보안 프레임워크 kShield 설계 및 구현

**이상헌**  
(소속 기관)  
lsh66404865@gmail.com

---

## 요약

대규모 언어 모델(LLM) 서비스가 확산됨에 따라 AI 추론 서버를 대상으로 한 보안 위협이 증가하고 있다. 기존 L7 애플리케이션 계층 방어는 HTTP 요청 필터링에 집중하여 커널 수준의 직접적인 파일 접근 공격에 취약하다는 한계를 지닌다. 본 논문은 eBPF(extended Berkeley Packet Filter)를 활용한 커널 수준 AI 모델 보안 프레임워크 kShield를 제안한다. kShield는 kprobe를 통해 `do_sys_openat2` 시스템 콜을 추적하고, AI 모델 파일에 대한 비정상적인 반복 접근을 탐지하여 악성 프로세스에 SIGKILL을 전송한다. llm-guard 기반 L7 방어(Group 1), kShield eBPF 단독(Group 2), 통합 시스템(Group 3)의 세 비교군을 구성하여 Ubuntu 22.04 VM 환경에서 실험하였다. 공격 시뮬레이션 결과 Group 1은 L7 필터 우회 후 최대 4,000 KB의 모델 데이터가 유출된 반면, Group 2와 Group 3은 80 KB 탈취 시점에 즉시 프로세스를 차단하였다. 10회 반복 측정 및 Welch's t-test 분석 결과 kShield eBPF 단독(Group 2)은 L7 단독(Group 1) 대비 통계적으로 유의미하게 높은 처리량을 보였으며(p=0.0192), L7+eBPF 통합(Group 3)은 L7 단독과 성능 차이가 없었다(p=0.3933). 정상 추론 워크로드 중 EVIL_OPEN 이벤트는 발생하지 않아 kShield가 정상 서비스를 간섭하지 않음을 확인하였다.

**핵심어:** eBPF, kprobe, AI 모델 보안, 커널 수준 보안, kShield, LLM 보안

---

## 1. 서론

ChatGPT, Claude 등 대규모 언어 모델 기반 서비스가 급속히 확산됨에 따라, AI 추론 서버와 모델 파일은 주요 공격 대상이 되고 있다. 기업은 수개월의 훈련 비용이 투입된 독점 모델 파일을 서버에 탑재하여 추론 서비스를 제공하며, 이 모델 파일의 탈취는 직접적인 지적 재산권 침해로 이어진다.

현재 산업계에서 주로 채택하는 보안 접근법은 HTTP 계층에서 프롬프트 인젝션 등 악성 요청을 탐지하는 L7(Layer 7) 방어이다. ProtectAI의 llm-guard [1], NVIDIA NeMo Guardrails [2] 등이 대표적이다. 그러나 이러한 방식은 정상적인 API 요청으로 위장한 공격이나, AI 서버 프로세스의 취약점을 이용한 직접 파일 시스템 접근에 대해서는 효과적으로 대응하지 못한다.

본 논문은 이러한 한계를 극복하기 위해 eBPF를 활용한 커널 수준 AI 모델 보안 프레임워크 kShield를 제안한다. eBPF는 커널 코드를 수정하지 않고 커널 이벤트를 실시간으로 추적하고 처리할 수 있는 기술로, 최근 보안 [3], 네트워크 [4], 관측 가능성 [5] 분야에서 광범위하게 활용되고 있다. kShield는 kprobe를 통해 파일 열기 시스템 콜을 후킹하여 AI 모델 파일에 대한 비정상적인 반복 접근을 탐지하고 악성 프로세스를 즉시 종료한다.

본 연구의 주요 기여는 다음과 같다.
- AI 모델 파일 보호에 특화된 eBPF 기반 커널 수준 보안 프레임워크 설계 및 구현
- L7 방어, eBPF 단독, L7+eBPF 통합의 3-way 비교 실험 설계
- 10회 반복 측정 및 Welch's t-test를 통한 통계적 유의성 검증
- bpftrace 기반 kprobe 발동 빈도 측정을 통한 오버헤드 근거 제시

---

## 2. 관련 연구

### 2.1 LLM 서비스 보안 위협 및 AI 모델 탈취 공격

Perez et al. [6]은 프롬프트 인젝션 공격이 LLM 기반 에이전트의 의도치 않은 행동을 유발할 수 있음을 최초로 체계화하였다. Greshake et al. [7]은 간접 프롬프트 인젝션을 통한 데이터 탈취 가능성을 실증하였다. 그러나 이들 연구는 L7 계층의 입력 조작에 집중하며, 커널 수준 파일 시스템 공격은 다루지 않는다.

AI 모델 파일 자체를 대상으로 한 탈취 위협 또한 심각하다. Tramèr et al. [11]은 머신러닝 모델의 예측 API를 반복 쿼리하여 모델 파라미터를 역추출하는 모델 스틸링 공격을 체계화하였으며, 이는 훈련 비용이 대규모 언어 모델에 집중되는 현재 환경에서 더욱 심각한 위협이 되고 있다. MITRE ATLAS [12]는 이러한 AI 시스템을 대상으로 한 적대적 공격 기법을 MITRE ATT&CK 프레임워크에 준하여 분류하고 있으며, 모델 탈취(Model Theft), 데이터 중독(Data Poisoning), 회피 공격(Evasion) 등을 주요 위협으로 제시한다. 기존 연구들은 API 계층에서의 공격에 집중하나, 서버 파일 시스템에 대한 직접 접근을 통한 모델 바이너리 탈취는 충분히 다루지 않는다는 한계가 있다.

### 2.2 L7 AI 보안 프레임워크

llm-guard [1]는 DeBERTa-v3 기반 모델로 프롬프트 인젝션을 탐지하는 오픈소스 라이브러리로, 임계값 기반 스코어링을 통해 악성 입력을 필터링한다. LangKit [8]은 통계적 방법으로 이상 프롬프트를 탐지한다. 이러한 L7 방어는 HTTP 요청 수준에서만 동작하므로, 서버 프로세스가 공격자의 제어하에 놓이거나 직접 파일 시스템 접근이 이루어질 경우 무력화된다.

### 2.3 eBPF 기반 보안 연구

eBPF를 활용한 런타임 보안 프레임워크는 최근 빠르게 발전하고 있다. Falco [9]는 eBPF를 활용하여 컨테이너 런타임 보안을 구현한 대표적 프레임워크로, 시스템 콜 수준에서 이상 행위를 탐지한다. Tetragon [13]은 Cilium 프로젝트의 eBPF 기반 보안 관측성 및 런타임 집행 도구로, 프로세스 실행, 파일 접근, 네트워크 이벤트를 커널 수준에서 모니터링하며 정책 위반 프로세스를 즉시 종료하는 기능을 제공한다. Tracee [14]는 Aqua Security가 개발한 eBPF 기반 런타임 보안 및 포렌식 도구로, 300개 이상의 이벤트 시그니처를 통해 Linux 커널 수준의 위협을 탐지한다. kShield [10]는 eBPF CO-RE 기반으로 커널 권한 상승 공격 기법을 탐지·차단하는 런타임 방어 프레임워크로, LKRG 대비 동등한 성능 오버헤드로 더 넓은 공격 유형을 방어함을 실증하였다.

Falco, Tetragon, Tracee가 범용 시스템 이벤트 모니터링에 초점을 두는 반면, 본 논문은 AI 모델 파일 경로에 특화된 접근 빈도 기반 탐지에 집중한다는 점에서 차별화된다. 이는 AI 추론 서버의 특성상 정상 워크로드에서 모델 파일 접근이 초기화 시 1회에 한정된다는 사실을 활용한 것이다.

### 2.4 커널 수준 파일 접근 제어

커널 수준에서 파일 접근을 제어하는 전통적 접근법으로는 Linux Security Modules (LSM) 프레임워크 [15]를 들 수 있다. LSM 기반의 SELinux, AppArmor 등은 강제 접근 제어(MAC) 정책을 통해 프로세스별 파일 접근 권한을 사전에 설정한다. 그러나 이러한 정책 기반 접근법은 정책 관리의 복잡성과 AI 모델 서버처럼 동적 접근 패턴이 있는 환경에서의 오탐(false positive) 위험이라는 한계가 있다. 본 논문이 제안하는 빈도 기반 이상 탐지 방식은 사전 정책 정의 없이 런타임에서 비정상적 패턴을 동적으로 식별한다는 점에서 보완적인 접근법을 제시한다.

---

## 3. kShield 설계 및 구현

### 3.1 위협 모델

본 논문이 상정하는 위협 모델은 다음과 같다. 공격자는 AI 추론 서버에 대한 네트워크 접근 권한을 보유하며, L7 필터를 우회하거나 취약한 디버그 엔드포인트를 통해 서버 프로세스에 임의의 코드를 실행시킬 수 있다. 궁극적 목표는 AI 모델 파일(`/opt/models/model.bin`)의 반복 읽기를 통한 데이터 탈취이다. 단, 커널 코드 자체를 수정하거나 루트킷을 삽입하는 공격은 본 논문의 범위 밖으로 한다.

### 3.2 시스템 아키텍처

kShield는 libbpf-bootstrap 프레임워크 기반으로 구현되었으며, 그림 1과 같이 커널 공간 BPF 프로그램과 사용자 공간 제어 데몬으로 구성된다.

```
┌─────────────────────────────────────────────┐
│              사용자 공간                      │
│  ┌──────────┐   perf buffer   ┌───────────┐ │
│  │ kShield  │◄────────────────│  이벤트   │ │
│  │  데몬    │                 │  핸들러   │ │
│  └──────────┘                 └───────────┘ │
├─────────────────────────────────────────────┤
│              커널 공간                        │
│  ┌─────────────────────────────────────────┐│
│  │  kprobe @ do_sys_openat2               ││
│  │  ┌─────────────────────────────────┐   ││
│  │  │ 파일명 매칭 → open_cnt 증가     │   ││
│  │  │ open_cnt ≥ 20 → SIGKILL 전송   │   ││
│  │  └─────────────────────────────────┘   ││
│  └─────────────────────────────────────────┘│
└─────────────────────────────────────────────┘
```

### 3.3 핵심 탐지 메커니즘 (EVIL_OPEN)

kShield의 핵심은 EVIL_OPEN 이벤트 탐지이다. `do_sys_openat2` 진입 시 커널 BPF 프로그램이 호출되어 다음 로직을 수행한다.

1. 열리는 파일의 경로를 보안 파일 목록(`security_files[]`)과 비교
2. 일치하는 경우 해당 프로세스의 `open_cnt` 증가
3. `open_cnt ≥ EVIL_OPEN_CNT(20)` 조건 충족 시 `bpf_send_signal(SIGKILL)` 호출
4. 100초 주기로 `open_cnt` 초기화 (오탐 방지)

보안 파일 목록은 `/opt/models/model.bin` 등 AI 모델 파일 경로로 구성되며, BPF rodata 섹션에 컴파일 타임에 삽입된다. 이는 보호 대상 파일 경로가 변경될 경우 BPF 프로그램을 재컴파일해야 함을 의미하며, 런타임 경로 설정을 지원하지 않는 구현 한계가 있다.

임계값 EVIL_OPEN_CNT=20은 4.6절 bpftrace 측정 결과에 기반한다. 정상 AI 추론 서버는 모델 파일을 서버 초기화 시 1회만 열고 이후 추론 과정에서는 추가로 열지 않는다. 따라서 임계값 20은 정상 동작 기준(1회) 대비 20배의 안전 여유(safety margin)를 확보하면서, 공격자가 의미 있는 모델 데이터를 탈취하기 위해 반복적으로 파일을 열어야 하는 시나리오를 포착한다.

### 3.4 L7 방어 통합

AI 추론 서버(`ai_server.py`)는 HTTP 계층에서 두 가지 방어를 제공한다.

- **키워드 필터링**: 정규식 기반 프롬프트 인젝션 탐지 (1,000자 초과 입력 차단 포함)
- **레이트 리미팅**: IP당 10초에 20회 초과 요청 차단 (DoS 방어 목적)

성능 벤치마크는 레이트 리미팅을 비활성화(`--no-ratelimit`)한 조건에서 수행하여 순수 추론 지연을 측정하였다. 레이트 리미팅은 실 운용 환경에서 L7 방어의 일부로 활성화된다.

---

## 4. 실험

### 4.1 실험 환경

| 항목 | 사양 |
|------|------|
| OS | Ubuntu 22.04 LTS |
| 커널 | Linux 6.x (BTF 지원) |
| CPU | 2 vCPU |
| 메모리 | 4 GB |
| 모델 파일 | /opt/models/model.bin (4 GB sparse) |
| eBPF 프레임워크 | libbpf v1.3.0 + libbpf-bootstrap |
| Python | 3.12 (venv) |

**실험 모델 파일 주의**: 실험에서는 4 GB 희소 파일(sparse file)을 AI 모델 파일로 사용하였다. 이는 실제 LLM 가중치 없이도 파일 크기·경로를 재현하여 탈취 시뮬레이션을 가능하게 하기 위한 것이다. 그러나 실제 GGUF/GGML 형식의 모델 파일은 메모리 매핑(mmap) 기반 접근 패턴을 사용하여 `open()` 호출 빈도 및 I/O 특성이 희소 파일과 다를 수 있으며, 이에 대한 추가 검증은 향후 연구 과제로 남긴다.

### 4.2 비교군 구성

| 비교군 | L7 방어 | eBPF (kShield) | 설명 |
|--------|---------|---------------|------|
| Group 1 | ✓ | ✗ | 기존 L7 AI 보안 단독 |
| Group 2 | ✗ | ✓ | kShield eBPF 단독 |
| Group 3 | ✓ | ✓ | L7 + eBPF 통합 (제안 시스템) |

### 4.3 공격 시뮬레이션

공격 스크립트(`attack.py`)는 4단계로 구성된다.

- **Phase 1**: L7 키워드 직접 공격 (차단 예상)
- **Phase 2**: 취약 디버그 엔드포인트(`/api/v2/predict`) 접근 (L7 우회)
- **Phase 3**: 직접 파일 반복 읽기 (모델 탈취 시뮬레이션, count=1,000)
- **Phase 4**: 고속 `open()` 연속 호출 (EVIL_OPEN 탐지 유도)

### 4.4 공격 탐지 결과

| 비교군 | Phase 1 | Phase 2 | Phase 3 (모델 탈취) | Phase 4 |
|--------|---------|---------|-------------------|---------|
| Group 1 | 차단 | 우회 성공 | **4,000 KB 탈취** | 차단 불가 |
| Group 2 | 통과 | 통과 | **80 KB 후 즉시 차단** (SIGKILL) | 즉시 차단 |
| Group 3 | 차단 | 우회 시도 | **80 KB 후 즉시 차단** (SIGKILL) | 즉시 차단 |

Group 1은 L7 필터를 우회한 Phase 2 이후 직접 파일 접근이 가능하여, Phase 3에서 약 4,000 KB의 모델 데이터가 탈취되었다. Group 2와 Group 3은 파일 열기 횟수가 임계값(20회)에 도달하는 순간 악성 프로세스를 즉시 종료하여 탈취량을 약 80 KB로 제한하였다.

**주의**: Group 2(eBPF 단독)는 설계상 L7 방어를 포함하지 않으므로 Phase 1/2의 프롬프트 인젝션 및 취약 엔드포인트 공격을 차단하지 않는다. 이는 의도된 실험 구성으로, eBPF 단독의 파일 시스템 수준 방어 능력을 순수 측정하기 위한 것이다. 실 운용 환경에서는 Group 3(L7+eBPF 통합) 구성이 권장된다.

### 4.5 성능 오버헤드 분석 (반복 측정 및 통계 검증)

단일 측정의 우연성을 배제하기 위해 각 비교군별로 동일 조건에서 10회 반복 벤치마크(요청 500회/런)를 수행하고, Welch's t-test를 통해 군 간 차이의 통계적 유의성을 검증하였다.

**[표 1] 비교군별 성능 측정 결과 (N=10, 평균±표준편차)**

| 비교군 | 처리량 (req/s) | 지연시간 (ms) |
|--------|--------------|-------------|
| Group 1 (L7 단독) | 674.70 ± 7.02 | 1.416 ± 0.013 |
| Group 2 (eBPF 단독) | 703.30 ± 31.61 | 1.361 ± 0.064 |
| Group 3 (L7+eBPF 통합) | 683.39 ± 29.97 | 1.400 ± 0.059 |

**[표 2] Welch's t-test 결과**

| 비교 | 처리량 t-통계 | p-값 | 유의성 |
|------|------------|------|--------|
| Group 1 vs Group 2 | -2.793 | 0.0192 | * |
| Group 1 vs Group 3 | -0.892 | 0.3933 | ns |
| Group 2 vs Group 3 | +1.446 | 0.1655 | ns |

*기준: \*p<0.05, \*\*p<0.01, \*\*\*p<0.001, ns=유의하지 않음*

kShield eBPF 단독(Group 2: 703.30±31.61 req/s)은 L7 방어 단독(Group 1: 674.70±7.02 req/s) 대비 통계적으로 유의미하게 높은 처리량을 보였다(p=0.0192). 이는 커널 수준 eBPF 모니터링이 애플리케이션 계층 L7 필터링보다 낮은 오버헤드를 가짐을 시사한다. L7+eBPF 통합(Group 3: 683.39±29.97 req/s)과 L7 단독(Group 1) 간 Welch's t-test에서 유의미한 성능 저하는 확인되지 않았다(p=0.3933). 단, p>0.05는 "차이가 없음"을 증명하는 것이 아니라 "차이를 기각하지 못한 것"임을 유의해야 한다. 완전한 동등성 주장을 위해서는 동등성 검정(TOST; Two One-Sided Tests)이 추가적으로 요구되며, 이는 향후 연구 과제로 남긴다. 그러나 현재 N=10 조건에서 eBPF 추가로 인한 유의미한 성능 저하가 관측되지 않았다는 점은, kShield가 기존 L7 방어 인프라에 부담 없이 병행 적용 가능함을 보여주는 실용적 근거로 삼을 수 있다.

### 4.6 kprobe 발동 빈도 및 오버헤드 분석

kShield kprobe 훅의 실제 발동 빈도를 정량화하기 위해 bpftrace를 활용하여 정상 추론 워크로드(693 req/s, 500회 요청) 수행 중 `do_sys_openat2` 호출 횟수를 측정하였다.

**[표 3] 정상 추론 워크로드 중 kprobe 발동 현황**

| 구분 | 측정값 |
|------|--------|
| 유휴 상태 kprobe/s | ~14회 (시스템 백그라운드) |
| 벤치마크 중 최대 kprobe/s | 2,813회 |
| 요청당 평균 kprobe 발동 | 약 4.0회 |
| 모델 파일 open() 횟수 | 0회 (서버 초기화 시 1회 한정) |
| EVIL_OPEN 이벤트 발생 | 0건 (500회 전체 요청) |

정상 AI 추론 워크로드에서 `do_sys_openat2` kprobe는 초당 최대 2,813회 발동하였으나, 이는 Python HTTP 서버의 내부 파일 연산에 의한 것으로 AI 모델 파일에 대한 접근은 서버 초기화 시 1회에 한정되었다. 결과적으로 500회 전체 추론 요청에서 EVIL_OPEN 이벤트는 단 한 건도 발생하지 않았으며, kprobe 훅은 파일명 비교 후 즉시 반환하는 O(1) 조건 검사만 수행하였다. 이는 kShield가 정상 워크로드를 간섭하지 않으면서 공격 시에만 선택적으로 개입함을 실증한다.

단, 이 오탐률 측정은 Python HTTP 기반 추론 서버가 단일 모델 파일을 고정 로드하는 단일 시나리오에 한정된다. 모델 핫스왑(hot-swap), 다중 모델 서빙, 또는 빈번한 서버 재기동 환경에서는 초기화 시 `open()` 호출이 복수 발생할 수 있으며, 이 경우 임계값 조정이 필요하다. 다양한 실 운용 시나리오에서의 오탐률 측정은 향후 연구 과제로 남긴다.

---

## 5. 결론 및 향후 연구

본 논문은 eBPF kprobe를 활용하여 AI 모델 파일에 대한 비정상적인 반복 접근을 탐지·차단하는 커널 수준 보안 프레임워크 kShield를 제안하였다. 실험 결과 기존 L7 방어 단독 구성(Group 1)은 직접 파일 접근 공격에 취약하여 4,000 KB의 모델 데이터가 탈취된 반면, kShield를 포함한 구성(Group 2, 3)은 탈취를 80 KB로 제한하였다. 10회 반복 측정과 Welch's t-test를 통해 kShield eBPF 단독이 L7 단독 대비 성능상 우위를 가지며(p=0.0192), 통합 시스템은 L7 단독과 성능 차이가 없음을 검증하였다(p=0.3933). bpftrace 측정 결과 정상 추론 워크로드 500회에서 EVIL_OPEN 이벤트가 발생하지 않아 kShield가 정상 서비스에 영향을 주지 않음을 확인하였다.

향후 연구 과제는 다음과 같다.
- **공격 회피 시나리오 대응**: 19회 이하 반복 접근을 여러 프로세스에 분산하는 우회 공격에 대한 크로스-프로세스 집계 탐지 메커니즘 연구
- **open_cnt 리셋 주기 고도화**: 현재 100초 고정 주기로 `open_cnt`를 초기화하는 설계는, 공격자가 이 주기를 인지하여 임계값 미만의 접근을 시간적으로 분산하는 우회 가능성을 내포한다. 슬라이딩 윈도우(sliding window) 기반 빈도 집계로 전환하면 이 취약점을 근본적으로 해소할 수 있다.
- **동등성 검정(TOST) 수행**: Group 1 vs Group 3 간 성능 동등성을 통계적으로 엄밀히 증명하기 위해 Two One-Sided Tests 기반 동등성 검정과 표본 크기 확대(N≥30)가 필요하다.
- **실제 LLM 모델 환경 적용**: 4 GB 희소 파일 대신 실제 GGUF/GGML 형식 모델 파일을 사용한 추가 검증
- **임계값 자동 조정**: 워크로드 특성에 따른 EVIL_OPEN_CNT 동적 튜닝
- **런타임 경로 설정 지원**: 현재 보호 대상 파일 경로는 컴파일 타임에 BPF rodata에 고정된다. BPF map을 통한 런타임 경로 갱신 메커니즘을 도입하면 재컴파일 없이 보호 대상 모델 파일을 동적으로 추가·변경할 수 있다.
- **다양한 워크로드 시나리오 오탐률 검증**: 현재 오탐률 측정은 단일 모델 고정 로드 환경에 한정된다. 모델 핫스왑·다중 모델 서빙 등 다양한 실 운용 패턴에서의 오탐률을 추가로 측정하여 임계값 일반화 가능성을 검증할 필요가 있다.

---

## 참고문헌

[1] ProtectAI, "llm-guard: The Security Toolkit for LLM Interactions," GitHub, 2024.  
[2] NVIDIA, "NeMo Guardrails: An Open-Source Toolkit for Controllable and Safe LLM Applications," 2023.  
[3] Gregg, B., "BPF Performance Tools," Addison-Wesley, 2019.  
[4] Vieira, M. A. M. et al., "Fast Packet Processing with eBPF and XDP," ACM Computing Surveys, 2020.  
[5] Cilium, "eBPF-based Networking, Observability, Security," GitHub, 2024.  
[6] Perez, F. and Ribeiro, I., "Ignore Previous Prompt: Attack Techniques For Language Models," NeurIPS ML Safety Workshop, 2022.  
[7] Greshake, K. et al., "Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection," AISec Workshop, 2023.  
[8] whylabs, "LangKit: An Open-Source Text Metrics Toolkit for Language Models," GitHub, 2023.  
[9] Falco, "Container Runtime Security," The Falco Authors, CNCF, 2024.  
[10] G. Duan, B. Chen, Z. Chen, J. Sun, and H. Chen, "KSHIELD: An eBPF Runtime Defence Framework for Linux Kernel Privilege Escalation Attacks," Preprint submitted to Elsevier, SSRN 5871506, 2025.  
[11] F. Tramèr, F. Zhang, A. Juels, M. K. Reiter, and T. Ristenpart, "Stealing Machine Learning Models via Prediction APIs," in Proc. USENIX Security Symposium, 2016, pp. 601–618.  
[12] MITRE, "MITRE ATLAS: Adversarial Threat Landscape for AI Systems," MITRE Corporation, 2023. [Online]. Available: https://atlas.mitre.org  
[13] Isovalent, "Tetragon: eBPF-based Security Observability and Runtime Enforcement," GitHub, 2023. [Online]. Available: https://github.com/cilium/tetragon  
[14] Aqua Security, "Tracee: Linux Runtime Security and Forensics using eBPF," GitHub, 2024. [Online]. Available: https://github.com/aquasecurity/tracee  
[15] C. Wright, C. Cowan, S. Smalley, J. Morris, and G. Kroah-Hartman, "Linux Security Modules: General Security Support for the Linux Kernel," in Proc. USENIX Security Symposium, 2002, pp. 17–31.
