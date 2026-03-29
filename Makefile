.PHONY: test lint build install clean

install:
	pip install -e ".[dev]"

test:
	pytest tests/ -v --cov=. --cov-report=term-missing --cov-fail-under=80

test-fast:
	pytest tests/ -v

test-html:
	pytest tests/ -v --cov=. --cov-report=html --cov-fail-under=80

lint:
	ruff check .

build:
	python -m build

test-diff:
	python -m cli.main run --v1-har tests/fixtures/enum_rename/v1.har --v2-har tests/fixtures/enum_rename/v2.har --out-dir apidiff-demo


clean:
	rm -rf dist/ build/ *.egg-info .coverage htmlcov/ .pytest_cache/ __pycache__
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
