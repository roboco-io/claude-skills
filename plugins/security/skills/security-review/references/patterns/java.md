# Java Security Patterns

OWASP Top 10 2025 기반 Java 취약점 패턴 및 수정 방법.

## A01: Broken Access Control

### 취약 패턴
```java
// Missing authorization
@GetMapping("/api/users/{id}")
public User getUser(@PathVariable Long id) {
    return userRepository.findById(id).orElseThrow();
}

// SSRF
@GetMapping("/fetch")
public String fetchUrl(@RequestParam String url) throws IOException {
    return new URL(url).openStream().toString();
}
```

### 안전한 패턴
```java
// With authorization
@GetMapping("/api/users/{id}")
@PreAuthorize("hasRole('ADMIN') or #id == authentication.principal.id")
public User getUser(@PathVariable Long id) {
    return userRepository.findById(id).orElseThrow();
}

// Alternative: programmatic check
@GetMapping("/api/users/{id}")
public User getUser(@PathVariable Long id, Authentication auth) {
    User currentUser = (User) auth.getPrincipal();
    if (!currentUser.getId().equals(id) && !currentUser.isAdmin()) {
        throw new AccessDeniedException("Forbidden");
    }
    return userRepository.findById(id).orElseThrow();
}

// SSRF Prevention
private static final Set<String> ALLOWED_HOSTS = Set.of("api.example.com");

@GetMapping("/fetch")
public String fetchUrl(@RequestParam String url) throws IOException {
    URL parsedUrl = new URL(url);
    if (!ALLOWED_HOSTS.contains(parsedUrl.getHost())) {
        throw new IllegalArgumentException("Host not allowed");
    }
    return new URL(url).openStream().toString();
}
```

## A02: Security Misconfiguration

### 취약 패턴
```yaml
# application.yml
server:
  ssl:
    enabled: false

spring:
  security:
    user:
      password: admin  # Default credential
```

```java
// Permissive CORS
@Bean
public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration config = new CorsConfiguration();
    config.addAllowedOrigin("*");
    config.addAllowedMethod("*");
    return source;
}
```

### 안전한 패턴
```yaml
# application.yml
server:
  ssl:
    enabled: true
    key-store: classpath:keystore.p12

spring:
  security:
    user:
      password: ${ADMIN_PASSWORD}
```

```java
// Restrictive CORS
@Bean
public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration config = new CorsConfiguration();
    config.setAllowedOrigins(List.of("https://app.example.com"));
    config.setAllowedMethods(List.of("GET", "POST"));
    config.setAllowCredentials(true);
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", config);
    return source;
}

// Security headers
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.headers(headers -> headers
        .contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'self'"))
        .frameOptions(frame -> frame.deny())
        .xssProtection(xss -> xss.enable())
    );
    return http.build();
}
```

## A04: Cryptographic Failures

### 취약 패턴
```java
// Weak hash algorithm
MessageDigest md = MessageDigest.getInstance("MD5");
byte[] hash = md.digest(password.getBytes());

// Weak encryption
Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
SecretKey key = new SecretKeySpec("12345678".getBytes(), "DES");

// Hardcoded secrets
private static final String API_KEY = "sk-1234567890";
```

### 안전한 패턴
```java
// Strong password hashing with BCrypt
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);
String hash = encoder.encode(password);
boolean valid = encoder.matches(password, hash);

// Strong encryption with AES-GCM
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
SecretKey key = keyGenerator.generateKey();  // From secure key management
byte[] iv = new byte[12];
secureRandom.nextBytes(iv);
cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));

// Environment-based secrets
@Value("${api.key}")
private String apiKey;
```

## A05: Injection

### 취약 패턴
```java
// SQL Injection
String query = "SELECT * FROM users WHERE id = " + userId;
Statement stmt = connection.createStatement();
ResultSet rs = stmt.executeQuery(query);

// Command Injection
Runtime.getRuntime().exec("convert " + filename + " output.png");

// LDAP Injection
String filter = "(uid=" + username + ")";
ctx.search("ou=users", filter, controls);

// XPath Injection
String xpath = "//users/user[@id='" + userId + "']";
```

### 안전한 패턴
```java
// Parameterized query
String query = "SELECT * FROM users WHERE id = ?";
PreparedStatement stmt = connection.prepareStatement(query);
stmt.setLong(1, userId);
ResultSet rs = stmt.executeQuery();

// JPA/Hibernate (safe by default)
@Query("SELECT u FROM User u WHERE u.id = :id")
User findById(@Param("id") Long id);

// Safe command execution
ProcessBuilder pb = new ProcessBuilder("convert", inputPath, outputPath);
pb.redirectErrorStream(true);
Process p = pb.start();

// LDAP Injection Prevention
String sanitizedUsername = username.replaceAll("[^a-zA-Z0-9]", "");
String filter = "(uid={0})";
ctx.search("ou=users", filter, new Object[]{sanitizedUsername}, controls);
```

## A07: Authentication Failures

### 취약 패턴
```java
// Session fixation vulnerability
@PostMapping("/login")
public String login(HttpSession session, @RequestBody LoginRequest req) {
    if (authenticate(req)) {
        session.setAttribute("user", req.getUsername());
        return "success";
    }
    return "failure";
}

// No brute force protection
@PostMapping("/login")
public ResponseEntity<?> login(@RequestBody LoginRequest request) {
    return authService.authenticate(request);
}
```

### 안전한 패턴
```java
// Session fixation prevention
@PostMapping("/login")
public String login(HttpServletRequest request, @RequestBody LoginRequest req) {
    if (authenticate(req)) {
        request.changeSessionId();  // Create new session ID
        request.getSession().setAttribute("user", req.getUsername());
        return "success";
    }
    return "failure";
}

// Rate limiting with Bucket4j
@PostMapping("/login")
public ResponseEntity<?> login(@RequestBody LoginRequest request) {
    Bucket bucket = rateLimiter.resolveBucket(request.getUsername());
    if (!bucket.tryConsume(1)) {
        return ResponseEntity.status(429).body("Too many attempts");
    }
    return authService.authenticate(request);
}

// Spring Security session management
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.sessionManagement(session -> session
        .sessionFixation().newSession()
        .maximumSessions(1)
        .expiredUrl("/login?expired")
    );
    return http.build();
}
```

## A08: Software/Data Integrity Failures

### 취약 패턴
```java
// Unsafe deserialization
ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
Object obj = ois.readObject();  // Remote code execution!

// XML External Entity (XXE)
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
Document doc = factory.newDocumentBuilder().parse(xmlInput);
```

### 안전한 패턴
```java
// Safe deserialization with allowlist
ObjectInputStream ois = new ObjectInputStream(request.getInputStream()) {
    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
        if (!ALLOWED_CLASSES.contains(desc.getName())) {
            throw new InvalidClassException("Unauthorized class", desc.getName());
        }
        return super.resolveClass(desc);
    }
};

// Or use serialization filters (Java 9+)
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
    "com.example.dto.*;!*"
);
ois.setObjectInputFilter(filter);

// XXE Prevention
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
```

## A09: Security Logging Failures

### 취약 패턴
```java
// No logging
public boolean authenticate(String username, String password) {
    return userService.validate(username, password);
}

// Logging sensitive data
logger.info("Login: username={}, password={}", username, password);

// Using System.out
System.out.println("Error: " + e.getMessage());
```

### 안전한 패턴
```java
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

private static final Logger securityLogger = LoggerFactory.getLogger("SECURITY");

public boolean authenticate(String username, String password) {
    boolean success = userService.validate(username, password);

    securityLogger.info("Authentication attempt: username={}, success={}, ip={}",
        username, success, request.getRemoteAddr());

    if (!success) {
        securityLogger.warn("Failed login attempt: username={}, ip={}",
            username, request.getRemoteAddr());
    }

    return success;
}

// Structured logging with MDC
MDC.put("requestId", UUID.randomUUID().toString());
MDC.put("userId", currentUser.getId());
try {
    securityLogger.info("Sensitive operation performed");
} finally {
    MDC.clear();
}
```

## A10: Mishandling Exceptional Conditions

### 취약 패턴
```java
// Exposing stack traces
@ExceptionHandler(Exception.class)
public ResponseEntity<String> handleException(Exception e) {
    return ResponseEntity.status(500).body(e.getMessage() + "\n" +
        Arrays.toString(e.getStackTrace()));
}

// Swallowing exceptions
try {
    processData();
} catch (Exception e) {
    // Do nothing
}

// Unbounded operations
public void processItems(List<Item> items) {
    for (Item item : items) {  // No limit
        process(item);
    }
}
```

### 안전한 패턴
```java
// Generic error response
@ExceptionHandler(Exception.class)
public ResponseEntity<ErrorResponse> handleException(Exception e) {
    String errorId = UUID.randomUUID().toString();
    logger.error("Unhandled exception [{}]", errorId, e);
    return ResponseEntity.status(500)
        .body(new ErrorResponse("An error occurred", errorId));
}

// Proper exception handling
try {
    processData();
} catch (ValidationException e) {
    logger.warn("Validation failed: {}", e.getMessage());
    throw new BadRequestException("Invalid input");
} catch (DatabaseException e) {
    logger.error("Database error", e);
    throw new ServiceUnavailableException("Please try again later");
}

// Bounded operations
private static final int MAX_ITEMS = 1000;

public void processItems(List<Item> items) {
    if (items.size() > MAX_ITEMS) {
        throw new IllegalArgumentException("Too many items: max " + MAX_ITEMS);
    }
    items.stream().limit(MAX_ITEMS).forEach(this::process);
}
```
