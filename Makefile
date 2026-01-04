.PHONY: help install dev test lint format clean build publish

help:
	@echo "DNSSEC Security Tester - Available commands:"
	@echo ""
	@echo "  install       Install the package"
	@echo "  dev           Install for development"
	@echo "  test          Run tests"
	@echo "  test-cov      Run tests with coverage"
	@echo "  lint          Run code linting"
	@echo "  format        Format code with black"
	@echo "  clean         Clean build artifacts"
	@echo "  build         Build distribution"
	@echo "  publish       Publish to PyPI"

.DEFAULT_GOAL := help

install:
	pip install -e .

dev:
	pip install -e .
	pip install pytest pytest-cov black flake8 isort

test:
	pytest tests/ -v

test-cov:
	pytest tests/ -v --cov=dnssec_tester --cov-report=html --cov-report=term

lint:
	flake8 dnssec_tester tests --max-line-length=100

format:
	black dnssec_tester tests --line-length=100
	isort dnssec_tester tests

clean:
	rm -rf build/ dist/ *.egg-info
	rm -rf .pytest_cache/ .coverage htmlcov/
	find . -type d -name __pycache__ -exec rm -rf {} +
	build:
	python -m build

publish: build
	python -m twine upload dist/*
