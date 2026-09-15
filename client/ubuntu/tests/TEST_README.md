# UFW Local Agent - Testing Guide

## Setup

Install test dependencies:
```bash
pip install -r requirements.txt
```

## Running Tests

Run all tests:
```bash
./.venv/bin/python -m pytest tests -v
```

Run with coverage report:
```bash
./.venv/bin/python -m pytest tests --cov=src --cov-report=html
```

Run specific test class:
```bash
./.venv/bin/python -m pytest tests/test_app.py::TestRootEndpoint -v
```

Run specific test:
```bash
./.venv/bin/python -m pytest tests/test_app.py::TestRootEndpoint::test_root_returns_correct_structure -v
```

## Test Coverage

The test suite includes:

### **TestRootEndpoint**
- Tests the root endpoint returns correct structure with available endpoints

### **TestUFWStartEndpoint**
- Tests successful UFW start
- Tests start with error output

### **TestUFWStopEndpoint**
- Tests successful UFW stop

### **TestUFWStatusEndpoint**
- Tests successful status retrieval

### **TestRunUFWCommand**
- Tests non-root user error handling (403)
- Tests successful command execution
- Tests stderr output handling
- Tests UFW binary not found (500)
- Tests command execution failure (500)
- Tests command timeout (500)

### **TestIntegration**
- Tests complete workflow: status → stop → start

## Key Features

✅ All endpoints mocked for safe testing (no actual UFW execution)  
✅ Comprehensive error handling coverage  
✅ Integration tests for workflow validation  
✅ Root privilege validation  
✅ Timeout and failure scenarios  
✅ 100% API coverage
