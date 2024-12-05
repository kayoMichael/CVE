# Configuration Variables
PYTHON_VERSION := 3.11.0
VENV_DIR := .venv
PYTHON := $(VENV_DIR)/bin/python
PIP := $(VENV_DIR)/bin/pip
CVES_FILE := cve.txt

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

.PHONY: help
help:
	@echo "Available targets:"
	@echo "  all              - Set up the complete development environment"
	@echo "  check-python     - Verify Python installation"
	@echo "  create-venv      - Create Python virtual environment"
	@echo "  install-deps     - Install/update project dependencies"
	@echo "  clean           - Remove virtual environment and temporary files"
	@echo "  check-g4f       - Check and update g4f package if needed"
	@echo "  show-versions   - Display installed and latest g4f versions"
	@echo "  run             - Run the application with optional CVE file"

define get_latest_version
$(shell curl -s https://pypi.org/pypi/g4f/json | $(PYTHON) -c "import json, sys; print(json.load(sys.stdin)['info']['version'])")
endef

define get_installed_version
$(shell pip show g4f | findstr "Version:" 2>nul | $(PYTHON) -c "import sys; print(sys.stdin.read().split(': ')[1].strip())")
endef

G4F_INSTALLED_VERSION := $(call get_installed_version,INSTALLED)
G4F_LATEST_VERSION := $(call get_latest_version,LATEST)

.PHONY: all check-python install-python create-venv install-deps clean check-g4f show-versions run

all: check-python create-venv install-deps
	@echo "Setup complete! Use 'make run' to start the application."

check-python:
	@echo "Checking Python installation..."
	@if ! command -v python >/dev/null 2>&1; then \
		echo "Python not found. Installing Python..."; \
		$(MAKE) install-python; \
	else \
		echo "Python $(shell python --version) found."; \
	fi

install-python:
	@if command -v winget >/dev/null 2>&1; then \
		winget install -e --id Python.Python.3.11; \
		echo "Installed Python $(PYTHON_VERSION)"; \
	else \
		echo "Error: winget not found. Please install Python $(PYTHON_VERSION) manually from python.org"; \
		exit 1; \
	fi

create-venv:
	@echo "Setting up virtual environment..."
	@if [ ! -d "$(VENV_DIR)" ]; then \
		python -m venv $(VENV_DIR); \
		echo "Virtual environment created successfully."; \
	else \
		echo "Virtual environment already exists."; \
	fi

install-deps: create-venv
	@echo "Installing/updating dependencies..."
	@$(PIP) install --upgrade pip
	@$(PIP) install -r requirements.txt
	@echo "All dependencies are up to date!"

clean:
	@echo "Cleaning up..."
	@rm -rf $(VENV_DIR)
	@echo "Cleanup complete!"

check-g4f:
	@echo "Installed version: $(G4F_INSTALLED_VERSION)"
	@echo "Latest version: $(G4F_LATEST_VERSION)"
	@if [ "$(G4F_INSTALLED_VERSION)" != "$(G4F_LATEST_VERSION)" ]; then \
		echo "Updating g4f to latest version..."; \
		$(PIP) install --upgrade g4f; \
	else \
		echo "g4f is already at the latest version."; \
	fi

show-versions:
	@echo "Installed version: $(G4F_INSTALLED_VERSION)"
	@echo "Latest version: $(G4F_LATEST_VERSION)"

run:
    @$(MAKE) check-g4f
    @$(MAKE) show-versions
	@read -p "Enter the path to the CVE file (default: $(CVES_FILE)): " input_file; \
	file_to_use="$${input_file:-$(CVES_FILE)}"; \
	echo "Running with file: $$file_to_use"; \
	$(PYTHON) src/server.py "$$file_to_use"
