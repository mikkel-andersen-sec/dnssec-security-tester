# Contributing to DNSSEC Security Tester

Thank you for your interest in contributing! This document provides guidelines and instructions for contributing to the project.

## Code of Conduct

- Be respectful and professional
- Provide constructive feedback
- Focus on improving security and functionality
- Report security vulnerabilities responsibly

## Getting Started

### Prerequisites
- Python 3.8+
- Git
- pip

### Development Setup

```bash
# Clone the repository
git clone https://github.com/mikkel-andersen-sec/dnssec-security-tester.git
cd dnssec-security-tester

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -r requirements.txt
pip install pytest pytest-cov black flake8

# Run tests
pytest tests/
```

## Development Workflow

### 1. Create a Feature Branch

```bash
git checkout -b feature/your-feature-name
```

### 2. Make Your Changes

- Write clear, well-documented code
- Follow PEP 8 style guidelines
- Add docstrings to functions and classes
- Include type hints where applicable

### 3. Test Your Changes

```bash
# Run tests
pytest tests/

# Run with coverage
pytest --cov=dnssec_tester tests/

# Format code
black dnssec_tester/

# Check style
flake8 dnssec_tester/
```

### 4. Commit and Push

```bash
git add .
git commit -m "Brief description of changes"
git push origin feature/your-feature-name
```

### 5. Create a Pull Request

- Provide a clear description of changes
- Reference any related issues
- Ensure CI/CD checks pass

## Areas for Contribution

### Bug Fixes
- Report issues with clear reproduction steps
- Test fixes against existing test suite
- Update tests if behavior changes

### New Features
- Discuss major features in an issue first
- Add comprehensive tests
- Update documentation

### Documentation
- Improve README and guides
- Add examples and tutorials
- Fix typos and clarifications

### Testing
- Add unit tests
- Improve test coverage
- Add integration tests

### Performance
- Optimize slow operations
- Improve memory usage
- Document performance considerations

## Code Style Guidelines

### Python Style
- Follow PEP 8
- Use type hints for function parameters and returns
- Maximum line length: 100 characters
- Use f-strings for formatting

### Naming Conventions
- Classes: PascalCase (e.g., `DNSSECValidator`)
- Functions/Methods: snake_case (e.g., `validate_signature`)
- Constants: UPPER_SNAKE_CASE (e.g., `RECOMMENDED_ALGORITHMS`)
- Private members: prefix with underscore (e.g., `_internal_method`)

### Documentation
- Use docstrings for all public functions
- Format: Google-style docstrings
- Include type information
- Provide usage examples for complex functions

Example:
```python
def validate_domain(domain: str, timeout: int = 10) -> ValidationResult:
    """Validate DNSSEC for a domain.
    
    Args:
        domain: The domain name to validate
        timeout: Query timeout in seconds (default: 10)
    
    Returns:
        ValidationResult containing all validation findings
    
    Raises:
        ValueError: If domain format is invalid
        TimeoutError: If validation exceeds timeout
    
    Example:
        >>> result = validate_domain('example.com')
        >>> print(result.overall_status)
        'secure'
    """
    pass
```

## Commit Message Guidelines

Use clear, descriptive commit messages:

```
[TYPE] Brief description (50 chars max)

Detailed explanation of the change if needed.
Explain the motivation and context.

Related-To: #123
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `test`: Test additions/changes
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `chore`: Build/dependencies

## Testing Requirements

### Unit Tests
- Test individual functions
- Mock external dependencies
- Aim for >80% coverage
- Test both success and failure cases

### Integration Tests
- Test component interactions
- Test with real DNS queries (use test domains)
- Verify end-to-end workflows

### Test Organization
```
tests/
├── test_validator.py      # Validator unit tests
├── test_resolver.py       # Resolver unit tests
├── test_tester.py         # Main tester tests
├── test_cli.py            # CLI interface tests
└── fixtures/              # Test data
    ├── dnssec_keys.txt
    └── sample_zones/
```

## Security Considerations

### When Contributing
- Never hardcode secrets or credentials
- Sanitize user input
- Validate all external data
- Use secure defaults
- Consider attack vectors

### Reporting Security Issues

**Do not open public issues for security vulnerabilities!**

Email security details to: security@sentinelcybersecurity.com

Include:
- Description of vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if you have one)

## Release Process

Maintainers will:
1. Merge tested PRs
2. Update version number
3. Update CHANGELOG
4. Create release tag
5. Push to PyPI

Versioning follows [Semantic Versioning](https://semver.org/):
- MAJOR: Incompatible API changes
- MINOR: New functionality (backward compatible)
- PATCH: Bug fixes

## Questions or Need Help?

- Open a GitHub issue for questions
- Check existing issues first
- Ask on discussions if applicable
- Read documentation thoroughly

Thank you for contributing! Your efforts make this project better.
