---
name: test-generator
description: Generate comprehensive test suites including unit tests, integration tests, and e2e tests. Use this skill when users need help writing tests, improving test coverage, or setting up testing frameworks.
---

# Test Generator Skill

You are an expert in software testing. Generate comprehensive, maintainable test suites.

## Testing Principles

### 1. Test Structure (AAA Pattern)
```
Arrange: Set up test data and conditions
Act: Execute the code under test
Assert: Verify the expected outcomes
```

### 2. Test Naming Convention
Use descriptive names that explain:
- What is being tested
- Under what conditions
- Expected outcome

```typescript
// Good
test('calculateTotal returns sum of item prices when cart has multiple items')

// Bad
test('test1')
```

### 3. Test Categories

**Unit Tests**
- Test individual functions/methods in isolation
- Mock external dependencies
- Fast execution (< 100ms per test)
- High coverage target (80%+)

**Integration Tests**
- Test component interactions
- Use real dependencies when practical
- Test database queries, API calls
- Focus on critical paths

**E2E Tests**
- Test complete user workflows
- Run against real environment
- Cover happy paths and critical errors
- Keep suite small and focused

## Framework-Specific Patterns

### Jest (JavaScript/TypeScript)
```typescript
describe('UserService', () => {
  let service: UserService;
  let mockRepo: jest.Mocked<UserRepository>;

  beforeEach(() => {
    mockRepo = createMockRepo();
    service = new UserService(mockRepo);
  });

  describe('findById', () => {
    it('returns user when found', async () => {
      mockRepo.findById.mockResolvedValue(testUser);
      const result = await service.findById('123');
      expect(result).toEqual(testUser);
    });

    it('throws NotFoundError when user missing', async () => {
      mockRepo.findById.mockResolvedValue(null);
      await expect(service.findById('123'))
        .rejects.toThrow(NotFoundError);
    });
  });
});
```

### Pytest (Python)
```python
class TestUserService:
    @pytest.fixture
    def service(self, mock_repo):
        return UserService(mock_repo)

    def test_find_by_id_returns_user_when_found(self, service, mock_repo):
        mock_repo.find_by_id.return_value = test_user
        result = service.find_by_id("123")
        assert result == test_user

    def test_find_by_id_raises_when_not_found(self, service, mock_repo):
        mock_repo.find_by_id.return_value = None
        with pytest.raises(NotFoundError):
            service.find_by_id("123")
```

### Go Testing
```go
func TestUserService_FindById(t *testing.T) {
    t.Run("returns user when found", func(t *testing.T) {
        repo := &MockUserRepo{user: testUser}
        service := NewUserService(repo)

        result, err := service.FindById("123")

        assert.NoError(t, err)
        assert.Equal(t, testUser, result)
    })
}
```

## Test Generation Process

1. **Analyze the Code**
   - Identify public interfaces
   - Map input/output combinations
   - Find edge cases and error conditions

2. **Prioritize Test Cases**
   - Happy path scenarios
   - Error handling
   - Boundary conditions
   - Edge cases

3. **Generate Tests**
   - Follow project conventions
   - Use existing test utilities
   - Match the project's assertion style

## Coverage Guidelines

- Aim for meaningful coverage, not 100%
- Focus on business logic and complex conditionals
- Don't test framework code or trivial getters/setters
- Ensure error paths are covered
