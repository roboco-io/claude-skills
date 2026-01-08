# Go Security Patterns

OWASP Top 10 2025 기반 Go 취약점 패턴 및 수정 방법.

## A01: Broken Access Control

### 취약 패턴
```go
// IDOR - No ownership check
func GetUser(w http.ResponseWriter, r *http.Request) {
    id := r.URL.Query().Get("id")
    user, _ := db.GetUser(id)  // Anyone can access any user
    json.NewEncoder(w).Encode(user)
}

// SSRF
func FetchURL(w http.ResponseWriter, r *http.Request) {
    url := r.URL.Query().Get("url")
    resp, _ := http.Get(url)  // User-controlled URL
    io.Copy(w, resp.Body)
}
```

### 안전한 패턴
```go
// IDOR Fixed
func GetUser(w http.ResponseWriter, r *http.Request) {
    id := r.URL.Query().Get("id")
    currentUser := r.Context().Value("user").(*User)

    if id != currentUser.ID && !currentUser.IsAdmin {
        http.Error(w, "Forbidden", http.StatusForbidden)
        return
    }

    user, _ := db.GetUser(id)
    json.NewEncoder(w).Encode(user)
}

// SSRF Prevention
var allowedHosts = map[string]bool{
    "api.example.com": true,
    "cdn.example.com": true,
}

func FetchURL(w http.ResponseWriter, r *http.Request) {
    rawURL := r.URL.Query().Get("url")
    parsedURL, err := url.Parse(rawURL)
    if err != nil || !allowedHosts[parsedURL.Host] {
        http.Error(w, "Invalid URL", http.StatusBadRequest)
        return
    }

    client := &http.Client{Timeout: 5 * time.Second}
    resp, _ := client.Get(rawURL)
    io.Copy(w, resp.Body)
}
```

## A02: Security Misconfiguration

### 취약 패턴
```go
// No TLS
http.ListenAndServe(":8080", nil)

// Missing security headers
func handler(w http.ResponseWriter, r *http.Request) {
    w.Write([]byte("Hello"))
}

// Exposing sensitive paths
http.Handle("/debug/pprof/", http.DefaultServeMux)
```

### 안전한 패턴
```go
// TLS enabled
http.ListenAndServeTLS(":443", "cert.pem", "key.pem", nil)

// Security headers middleware
func securityHeaders(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("X-Content-Type-Options", "nosniff")
        w.Header().Set("X-Frame-Options", "DENY")
        w.Header().Set("X-XSS-Protection", "1; mode=block")
        w.Header().Set("Content-Security-Policy", "default-src 'self'")
        w.Header().Set("Strict-Transport-Security", "max-age=31536000")
        next.ServeHTTP(w, r)
    })
}

// Secure server configuration
server := &http.Server{
    Addr:         ":443",
    Handler:      securityHeaders(router),
    ReadTimeout:  5 * time.Second,
    WriteTimeout: 10 * time.Second,
    IdleTimeout:  120 * time.Second,
    TLSConfig: &tls.Config{
        MinVersion: tls.VersionTLS12,
        CipherSuites: []uint16{
            tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        },
    },
}
```

## A04: Cryptographic Failures

### 취약 패턴
```go
// Weak hash
import "crypto/md5"
hash := md5.Sum([]byte(password))

// Weak encryption
import "crypto/des"
block, _ := des.NewCipher(key[:8])

// Hardcoded secrets
const APIKey = "sk-1234567890"

// Insecure random
import "math/rand"
token := rand.Int63()
```

### 안전한 패턴
```go
// Strong password hashing with bcrypt
import "golang.org/x/crypto/bcrypt"

hash, _ := bcrypt.GenerateFromPassword([]byte(password), 12)
err := bcrypt.CompareHashAndPassword(hash, []byte(password))

// Strong encryption with AES-GCM
import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
)

block, _ := aes.NewCipher(key)
gcm, _ := cipher.NewGCM(block)
nonce := make([]byte, gcm.NonceSize())
rand.Read(nonce)
ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

// Environment-based secrets
apiKey := os.Getenv("API_KEY")
if apiKey == "" {
    log.Fatal("API_KEY required")
}

// Secure random
import "crypto/rand"
token := make([]byte, 32)
rand.Read(token)
```

## A05: Injection

### 취약 패턴
```go
// SQL Injection
query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", userID)
db.Query(query)

// Command Injection
cmd := exec.Command("sh", "-c", "convert "+filename+" output.png")
cmd.Run()

// Path Traversal
path := filepath.Join("/uploads", r.URL.Query().Get("file"))
http.ServeFile(w, r, path)
```

### 안전한 패턴
```go
// Parameterized query
db.Query("SELECT * FROM users WHERE id = $1", userID)

// Using sqlx or GORM (safe by default)
var user User
db.Where("id = ?", userID).First(&user)

// Safe command execution
allowedFormats := map[string]bool{"png": true, "jpg": true}
if !allowedFormats[format] {
    return errors.New("invalid format")
}
cmd := exec.Command("convert", inputPath, outputPath)
cmd.Run()

// Path Traversal Prevention
filename := filepath.Base(r.URL.Query().Get("file"))  // Strip directory
path := filepath.Join("/uploads", filename)
if !strings.HasPrefix(path, "/uploads/") {
    http.Error(w, "Invalid path", http.StatusBadRequest)
    return
}
http.ServeFile(w, r, path)
```

## A06: Insecure Design

### 취약 패턴
```go
// Race condition
var balance = make(map[string]int)

func Transfer(from, to string, amount int) {
    if balance[from] >= amount {
        balance[from] -= amount  // Race condition!
        balance[to] += amount
    }
}

// Concurrent map access
go func() {
    m["key"] = "value"  // Panic: concurrent map writes
}()
```

### 안전한 패턴
```go
// With mutex
var (
    balance = make(map[string]int)
    mu      sync.RWMutex
)

func Transfer(from, to string, amount int) error {
    mu.Lock()
    defer mu.Unlock()

    if balance[from] < amount {
        return errors.New("insufficient funds")
    }
    balance[from] -= amount
    balance[to] += amount
    return nil
}

// Using sync.Map for concurrent access
var m sync.Map

m.Store("key", "value")
value, ok := m.Load("key")
```

## A07: Authentication Failures

### 취약 패턴
```go
// Weak password comparison
if user.Password == inputPassword {
    // Logged in
}

// No session expiry
session := &Session{
    UserID: user.ID,
    // No expiry set
}

// No rate limiting
func LoginHandler(w http.ResponseWriter, r *http.Request) {
    // Direct authentication
}
```

### 안전한 패턴
```go
// Secure password verification
import "golang.org/x/crypto/bcrypt"

err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(inputPassword))
if err != nil {
    http.Error(w, "Invalid credentials", http.StatusUnauthorized)
    return
}

// Session with expiry
session := &Session{
    UserID:    user.ID,
    ExpiresAt: time.Now().Add(24 * time.Hour),
    Token:     generateSecureToken(),
}

// Rate limiting middleware
import "golang.org/x/time/rate"

var limiter = rate.NewLimiter(rate.Every(time.Minute/5), 5)  // 5 requests per minute

func RateLimitMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if !limiter.Allow() {
            http.Error(w, "Too many requests", http.StatusTooManyRequests)
            return
        }
        next.ServeHTTP(w, r)
    })
}
```

## A08: Software/Data Integrity Failures

### 취약 패턴
```go
// Unsafe deserialization with gob
var data interface{}
dec := gob.NewDecoder(r.Body)
dec.Decode(&data)  // Can be exploited

// Unpinned dependencies
go get example.com/pkg@master
```

### 안전한 패턴
```go
// Type-safe deserialization
type SafeData struct {
    Name  string `json:"name"`
    Value int    `json:"value"`
}

var data SafeData
if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
    http.Error(w, "Invalid input", http.StatusBadRequest)
    return
}

// go.mod with pinned versions
module myapp

go 1.21

require (
    example.com/pkg v1.2.3
)

// Verify checksums
go mod verify
```

## A09: Security Logging Failures

### 취약 패턴
```go
// Silently ignoring errors
result, _ := db.Query(query)

// No security logging
func Login(username, password string) bool {
    return authenticate(username, password)
}

// Logging sensitive data
log.Printf("Login: %s, %s", username, password)
```

### 안전한 패턴
```go
// Proper error handling and logging
import (
    "go.uber.org/zap"
)

logger, _ := zap.NewProduction()
defer logger.Sync()

func Login(username, password string, r *http.Request) bool {
    success := authenticate(username, password)

    logger.Info("authentication_attempt",
        zap.String("username", username),
        zap.Bool("success", success),
        zap.String("ip", r.RemoteAddr),
        zap.String("user_agent", r.UserAgent()),
    )

    if !success {
        logger.Warn("authentication_failure",
            zap.String("username", username),
            zap.String("ip", r.RemoteAddr),
        )
    }

    return success
}
```

## A10: Mishandling Exceptional Conditions

### 취약 패턴
```go
// Exposing internal errors
func handler(w http.ResponseWriter, r *http.Request) {
    result, err := db.Query(query)
    if err != nil {
        http.Error(w, err.Error(), 500)  // Exposes DB details
    }
}

// Unbounded operations
func ProcessItems(items []Item) {
    for _, item := range items {  // No limit
        process(item)
    }
}

// Panic without recovery
func handler(w http.ResponseWriter, r *http.Request) {
    data := r.URL.Query().Get("data")
    result := riskyOperation(data)  // May panic
    w.Write(result)
}
```

### 안전한 패턴
```go
// Generic error response
func handler(w http.ResponseWriter, r *http.Request) {
    result, err := db.Query(query)
    if err != nil {
        errorID := uuid.New().String()
        logger.Error("database_error",
            zap.Error(err),
            zap.String("error_id", errorID),
        )
        http.Error(w, fmt.Sprintf("An error occurred (ID: %s)", errorID), 500)
        return
    }
}

// Bounded operations
const MaxItems = 1000

func ProcessItems(items []Item) error {
    if len(items) > MaxItems {
        return fmt.Errorf("too many items: max %d", MaxItems)
    }
    for _, item := range items[:min(len(items), MaxItems)] {
        process(item)
    }
    return nil
}

// Recovery middleware
func RecoveryMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        defer func() {
            if err := recover(); err != nil {
                logger.Error("panic_recovered", zap.Any("error", err))
                http.Error(w, "Internal server error", 500)
            }
        }()
        next.ServeHTTP(w, r)
    })
}
```
