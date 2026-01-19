# JavaScript/TypeScript Security Patterns

OWASP Top 10 2025 기반 JavaScript/TypeScript 취약점 패턴 및 수정 방법.

## A01: Broken Access Control

### 취약 패턴
```javascript
// IDOR (Insecure Direct Object Reference)
app.get('/api/users/:id', (req, res) => {
  const user = db.findById(req.params.id);  // No ownership check
  res.json(user);
});

// SSRF
app.get('/fetch', async (req, res) => {
  const data = await fetch(req.query.url);  // User-controlled URL
  res.json(await data.json());
});
```

### 안전한 패턴
```javascript
// IDOR Fixed
app.get('/api/users/:id', (req, res) => {
  if (req.params.id !== req.user.id && !req.user.isAdmin) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  const user = db.findById(req.params.id);
  res.json(user);
});

// SSRF Fixed
const ALLOWED_HOSTS = ['api.example.com', 'cdn.example.com'];
app.get('/fetch', async (req, res) => {
  const url = new URL(req.query.url);
  if (!ALLOWED_HOSTS.includes(url.hostname)) {
    return res.status(400).json({ error: 'Invalid URL' });
  }
  const data = await fetch(url);
  res.json(await data.json());
});
```

## A02: Security Misconfiguration

### 취약 패턴
```javascript
// Permissive CORS
app.use(cors({ origin: '*' }));

// Missing security headers
app.get('/', (req, res) => {
  res.send('Hello');
});

// Debug mode in production
app.use(errorHandler({ log: true, dumpExceptions: true }));
```

### 안전한 패턴
```javascript
// Restrictive CORS
const allowedOrigins = ['https://app.example.com'];
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true
}));

// Security headers with helmet
import helmet from 'helmet';
app.use(helmet());
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"],
  }
}));
```

## A04: Cryptographic Failures

### 취약 패턴
```javascript
// Weak hash
const hash = crypto.createHash('md5').update(password).digest('hex');

// Hardcoded secrets
const JWT_SECRET = 'mysecretkey123';

// Storing sensitive data in localStorage
localStorage.setItem('authToken', token);
```

### 안전한 패턴
```javascript
// Strong password hashing
import bcrypt from 'bcrypt';
const hash = await bcrypt.hash(password, 12);
const isValid = await bcrypt.compare(password, hash);

// Environment-based secrets
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) throw new Error('JWT_SECRET required');

// HttpOnly cookies for tokens
res.cookie('authToken', token, {
  httpOnly: true,
  secure: true,
  sameSite: 'strict',
  maxAge: 3600000
});
```

## A05: Injection

### 취약 패턴
```javascript
// SQL Injection
const query = `SELECT * FROM users WHERE id = ${req.params.id}`;
db.query(query);

// Command Injection
const { exec } = require('child_process');
exec(`convert ${req.body.filename} output.png`);

// XSS
res.send(`<div>Welcome, ${req.query.name}</div>`);
element.innerHTML = userInput;

// NoSQL Injection
db.users.find({ username: req.body.username, password: req.body.password });
```

### 안전한 패턴
```javascript
// Parameterized query
db.query('SELECT * FROM users WHERE id = ?', [req.params.id]);

// Safe command execution
import { execFile } from 'child_process';
const allowedFormats = ['png', 'jpg', 'gif'];
if (allowedFormats.includes(format)) {
  execFile('convert', [inputPath, outputPath]);
}

// XSS Prevention
import { escape } from 'html-escaper';
res.send(`<div>Welcome, ${escape(req.query.name)}</div>`);
element.textContent = userInput;

// NoSQL Injection Prevention
if (typeof req.body.username !== 'string') {
  return res.status(400).json({ error: 'Invalid input' });
}
db.users.find({
  username: req.body.username,
  password: { $eq: req.body.password }  // Explicit comparison
});
```

## A07: Authentication Failures

### 취약 패턴
```javascript
// Weak password policy
if (password.length < 4) {
  return res.status(400).json({ error: 'Password too short' });
}

// No rate limiting
app.post('/login', (req, res) => {
  // Direct authentication attempt
});

// Session fixation
req.session.userId = user.id;  // No session regeneration
```

### 안전한 패턴
```javascript
// Strong password policy
import passwordValidator from 'password-validator';
const schema = new passwordValidator();
schema
  .is().min(12)
  .has().uppercase()
  .has().lowercase()
  .has().digits()
  .has().symbols()
  .has().not().spaces();

// Rate limiting
import rateLimit from 'express-rate-limit';
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 5,  // 5 attempts
  message: 'Too many login attempts'
});
app.post('/login', loginLimiter, authHandler);

// Session regeneration
req.session.regenerate((err) => {
  req.session.userId = user.id;
  res.redirect('/dashboard');
});
```

## A08: Software/Data Integrity Failures

### 취약 패턴
```javascript
// Prototype pollution via JSON.parse
const config = JSON.parse(userInput);
Object.assign(defaults, config);

// Unsafe deserialization
const data = require('node-serialize').unserialize(userInput);
```

### 안전한 패턴
```javascript
// Safe object merging
const config = JSON.parse(userInput);
const safeConfig = {
  allowedKey1: config.allowedKey1,
  allowedKey2: config.allowedKey2
};

// Validate structure
import Ajv from 'ajv';
const ajv = new Ajv();
const validate = ajv.compile(configSchema);
if (!validate(config)) {
  throw new Error('Invalid configuration');
}
```

## A09: Security Logging Failures

### 취약 패턴
```javascript
// No logging
app.post('/login', (req, res) => {
  if (authenticate(req.body)) {
    res.json({ success: true });
  }
});

// Logging sensitive data
console.log('Login attempt:', req.body);  // Logs password
```

### 안전한 패턴
```javascript
// Structured security logging
import winston from 'winston';

const securityLogger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [new winston.transports.File({ filename: 'security.log' })]
});

app.post('/login', (req, res) => {
  const result = authenticate(req.body);
  securityLogger.info({
    event: result ? 'login_success' : 'login_failure',
    username: req.body.username,  // No password
    ip: req.ip,
    userAgent: req.get('user-agent'),
    timestamp: new Date().toISOString()
  });
});
```

## A10: Mishandling Exceptional Conditions

### 취약 패턴
```javascript
// Exposing stack traces
app.use((err, req, res, next) => {
  res.status(500).json({
    error: err.message,
    stack: err.stack
  });
});

// Unbounded operations
async function processItems(items) {
  for (const item of items) {  // No limit
    await processItem(item);
  }
}
```

### 안전한 패턴
```javascript
// Generic error response
app.use((err, req, res, next) => {
  console.error(err);  // Log internally
  res.status(500).json({
    error: 'An unexpected error occurred',
    requestId: req.id  // For support reference
  });
});

// Bounded operations
const MAX_ITEMS = 1000;
async function processItems(items) {
  if (items.length > MAX_ITEMS) {
    throw new Error(`Maximum ${MAX_ITEMS} items allowed`);
  }
  for (const item of items.slice(0, MAX_ITEMS)) {
    await processItem(item);
  }
}
```
