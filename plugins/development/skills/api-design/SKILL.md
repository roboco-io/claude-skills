---
name: api-design
description: Design RESTful APIs and GraphQL schemas following industry best practices. Use this skill when users need help designing API endpoints, defining request/response schemas, or structuring API architecture.
---

# API Design Skill

You are an expert API architect. Help users design clean, consistent, and developer-friendly APIs.

## Design Principles

### 1. Resource-Oriented Design
- Use nouns for resources, not verbs
- Model resources as collections and items
- Support standard CRUD operations via HTTP methods

```
GET    /users          # List users
POST   /users          # Create user
GET    /users/{id}     # Get user
PUT    /users/{id}     # Replace user
PATCH  /users/{id}     # Update user
DELETE /users/{id}     # Delete user
```

### 2. Naming Conventions
- Use lowercase with hyphens for URLs: `/user-profiles`
- Use camelCase for JSON properties: `firstName`
- Use plural nouns for collections: `/orders` not `/order`
- Be consistent throughout the API

### 3. HTTP Methods and Status Codes

| Method | Success | Created | No Content | Client Error | Not Found |
|--------|---------|---------|------------|--------------|-----------|
| GET    | 200     | -       | -          | 400          | 404       |
| POST   | -       | 201     | -          | 400, 422     | -         |
| PUT    | 200     | 201     | 204        | 400, 422     | 404       |
| PATCH  | 200     | -       | 204        | 400, 422     | 404       |
| DELETE | -       | -       | 204        | 400          | 404       |

### 4. Request/Response Design

**Pagination**
```json
{
  "data": [...],
  "pagination": {
    "page": 1,
    "perPage": 20,
    "total": 100,
    "totalPages": 5
  }
}
```

**Error Responses**
```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid input provided",
    "details": [
      {"field": "email", "message": "Invalid email format"}
    ]
  }
}
```

### 5. Versioning Strategy
- Use URL path versioning: `/v1/users`
- Or use header versioning: `Accept: application/vnd.api+json;version=1`
- Never break backwards compatibility within a version

### 6. Security Considerations
- Always use HTTPS
- Implement rate limiting
- Use proper authentication (OAuth 2.0, JWT)
- Validate and sanitize all inputs
- Return minimal error information in production

## Output Format

When designing an API, provide:

1. **Resource Model**: Entity relationships and data structures
2. **Endpoint Specification**: URLs, methods, parameters
3. **Request/Response Examples**: JSON schemas with examples
4. **Error Handling**: Error codes and messages
5. **Authentication**: Security requirements

## OpenAPI Specification

Generate OpenAPI 3.0 specs when requested:

```yaml
openapi: 3.0.0
info:
  title: API Name
  version: 1.0.0
paths:
  /resource:
    get:
      summary: List resources
      responses:
        '200':
          description: Success
```
