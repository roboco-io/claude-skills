# OWASP Top 10 2025 Security Checklist

코드 리뷰 시 사용할 OWASP Top 10 2025 체크리스트.

## A01: Broken Access Control (접근 제어 실패)

**심각도**: Critical

### 체크리스트
- [ ] 모든 API 엔드포인트에 인가(Authorization) 검사가 있는가?
- [ ] 객체 참조 시 소유권 검증이 있는가? (IDOR 방지)
- [ ] 관리자 기능에 역할 기반 접근 제어가 적용되어 있는가?
- [ ] URL 직접 접근으로 권한 우회가 불가능한가?
- [ ] SSRF 방지를 위한 URL 화이트리스트가 있는가?

### 주요 탐지 패턴
```
- req.params.id 또는 request.args['id'] 직접 사용
- @GetMapping 또는 @PostMapping에 @PreAuthorize 누락
- fetch(userInput) 또는 http.Get(userInput) 패턴
```

---

## A02: Security Misconfiguration (보안 설정 오류)

**심각도**: High

### 체크리스트
- [ ] 프로덕션 환경에서 디버그 모드가 비활성화되어 있는가?
- [ ] 보안 헤더가 설정되어 있는가? (CSP, HSTS, X-Frame-Options)
- [ ] CORS 설정이 적절히 제한되어 있는가?
- [ ] 기본 자격증명이 변경되었는가?
- [ ] 에러 메시지가 내부 정보를 노출하지 않는가?
- [ ] TLS가 활성화되어 있는가?

### 주요 탐지 패턴
```
- debug=True, DEBUG=true
- cors({ origin: '*' })
- server.ssl.enabled=false
- http.ListenAndServe (TLS 없음)
```

---

## A03: Software Supply Chain Failures (소프트웨어 공급망 실패)

**심각도**: Critical

### 체크리스트
- [ ] 의존성 버전이 고정되어 있는가?
- [ ] 알려진 취약점이 있는 패키지가 없는가?
- [ ] 락파일(package-lock.json, go.sum 등)이 커밋되어 있는가?
- [ ] 사용자 입력으로 동적 패키지 설치가 불가능한가?
- [ ] CI/CD 파이프라인에서 의존성 검사가 수행되는가?

### 주요 탐지 패턴
```
- npm install <user-input>
- pip install --upgrade <user-input>
- go get pkg@master (버전 미지정)
- package.json에 ^, ~ 버전 범위
```

---

## A04: Cryptographic Failures (암호화 실패)

**심각도**: Critical

### 체크리스트
- [ ] 강력한 해시 알고리즘을 사용하는가? (bcrypt, argon2, SHA-256+)
- [ ] MD5, SHA1이 비밀번호나 민감 데이터에 사용되지 않는가?
- [ ] 시크릿/키가 하드코딩되어 있지 않은가?
- [ ] 민감 데이터가 전송 중 암호화되는가? (TLS)
- [ ] 민감 데이터가 저장 시 암호화되는가?
- [ ] 안전한 난수 생성기를 사용하는가?

### 주요 탐지 패턴
```
- crypto.createHash('md5'), hashlib.md5()
- MessageDigest.getInstance("MD5")
- crypto/des, DES, 3DES 사용
- const SECRET = "...", API_KEY = "..."
- math/rand, random.choice() (암호화 목적)
```

---

## A05: Injection (인젝션)

**심각도**: Critical

### 체크리스트
- [ ] SQL 쿼리에 파라미터화된 쿼리를 사용하는가?
- [ ] 사용자 입력이 eval()이나 유사 함수에 전달되지 않는가?
- [ ] 시스템 명령 실행 시 입력이 이스케이프/검증되는가?
- [ ] XSS 방지를 위한 출력 인코딩이 적용되어 있는가?
- [ ] innerHTML 대신 textContent를 사용하는가?

### 주요 탐지 패턴
```
- "SELECT * FROM ... WHERE id = " + input
- cursor.execute("..." + input)
- exec(), eval(), os.system(), Runtime.exec()
- innerHTML = userInput
- render_template_string(userInput)
```

---

## A06: Insecure Design (안전하지 않은 설계)

**심각도**: High

### 체크리스트
- [ ] 위협 모델링이 수행되었는가?
- [ ] 경쟁 상태(Race Condition) 방지 메커니즘이 있는가?
- [ ] 비즈니스 로직 검증이 서버 측에서 수행되는가?
- [ ] 파일 업로드 시 타입/크기 검증이 있는가?
- [ ] 중요 작업에 재인증이 필요한가?

### 주요 탐지 패턴
```
- 뮤텍스/락 없는 공유 상태 접근
- goroutine에서 sync.Mutex 미사용
- 클라이언트 측 검증만 존재
- 파일 확장자 검증 없는 업로드
```

---

## A07: Authentication Failures (인증 실패)

**심각도**: Critical

### 체크리스트
- [ ] 강력한 비밀번호 정책이 적용되어 있는가?
- [ ] 로그인 시도 제한(Rate Limiting)이 있는가?
- [ ] 세션 고정 공격 방지를 위해 로그인 후 세션이 재생성되는가?
- [ ] 세션 만료 시간이 적절한가?
- [ ] 비밀번호가 평문으로 비교되지 않는가?
- [ ] 자격증명이 하드코딩되어 있지 않는가?

### 주요 탐지 패턴
```
- if (password === 'admin123')
- session.setAttribute() 후 invalidate() 없음
- password: ${ADMIN_PASSWORD:admin}
- 로그인 엔드포인트에 rate limiter 없음
```

---

## A08: Software/Data Integrity Failures (소프트웨어/데이터 무결성 실패)

**심각도**: High

### 체크리스트
- [ ] 안전하지 않은 역직렬화가 없는가? (pickle, ObjectInputStream)
- [ ] YAML 로드 시 safe_load를 사용하는가?
- [ ] CI/CD 파이프라인이 보호되어 있는가?
- [ ] 서명되지 않은 업데이트를 받지 않는가?
- [ ] Prototype Pollution 취약점이 없는가?

### 주요 탐지 패턴
```
- pickle.loads(userData)
- yaml.load(data) (safe_load가 아닌)
- ObjectInputStream.readObject()
- JSON.parse() 후 Object.assign()
```

---

## A09: Security Logging & Alerting Failures (보안 로깅/알림 실패)

**심각도**: Medium

### 체크리스트
- [ ] 인증 이벤트(성공/실패)가 로깅되는가?
- [ ] 접근 제어 실패가 로깅되는가?
- [ ] 로그에 민감 정보(비밀번호, 토큰)가 포함되지 않는가?
- [ ] 구조화된 로깅 형식을 사용하는가?
- [ ] 로그가 중앙 집중식으로 관리되는가?

### 주요 탐지 패턴
```
- console.log() 만 사용
- print(error)
- System.out.println()
- 인증 함수에 로깅 없음
- log.Printf("password: %s", password)
```

---

## A10: Mishandling Exceptional Conditions (예외 상황 오처리)

**심각도**: Medium

### 체크리스트
- [ ] 스택 트레이스가 사용자에게 노출되지 않는가?
- [ ] 예외가 묵시적으로 무시되지 않는가?
- [ ] 무한 루프/재귀에 대한 제한이 있는가?
- [ ] 리소스 사용량에 제한이 있는가?
- [ ] 에러 발생 시 안전한 기본값으로 폴백하는가?

### 주요 탐지 패턴
```
- catch(e) { res.send(e.stack) }
- except: pass
- e.printStackTrace()를 응답에 포함
- while(true) 또는 무한 재귀
- if err != nil { } (무시)
```

---

## 리뷰 우선순위

| 우선순위 | 카테고리 | 이유 |
|----------|----------|------|
| 1 | A05 Injection | 원격 코드 실행 가능 |
| 2 | A01 Broken Access Control | 데이터 유출/권한 상승 |
| 3 | A07 Authentication Failures | 계정 탈취 |
| 4 | A04 Cryptographic Failures | 민감 데이터 노출 |
| 5 | A08 Integrity Failures | 역직렬화 공격 |
| 6 | A03 Supply Chain | 의존성 취약점 |
| 7 | A06 Insecure Design | 설계 결함 |
| 8 | A02 Misconfiguration | 설정 오류 |
| 9 | A09 Logging Failures | 탐지 불가 |
| 10 | A10 Exception Handling | 정보 노출 |
