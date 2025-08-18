# We're using Make as a command runner, so always make (avoids need for .PHONY)
MAKEFLAGS += --always-make

PROJECT := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
SRC := $(PROJECT)src

export UV_PROJECT = $(SRC)
export PYTHONPATH = $(PROJECT):$(SRC)


help:  # Display help
	@echo "Usage: make [target] [ARGS='additional args']\n\nTargets:"
	@awk -F'#' '/^[a-z-]+:/ { sub(":.*", "", $$1); print " ", $$1, "#", $$2 }' Makefile | column -t -s '#'

all: fmt lint unit  # Run all quick, local commands

fmt:  # Format the Python code
	uv tool run ruff check --fix $(PROJECT)
	uv tool run ruff format $(PROJECT)

lint:  # Check for linting issues
	uv tool run ruff check $(SRC)
	uv tool run ruff format --check --diff $(SRC)
	uv run --extra dev pyright $(SRC)

unit:  # Run unit tests, for example: make unit ARGS='-k test_prepare_collect'
	uv run --no-managed-python --all-extras coverage run --source=$(PROJECT)/tests -m pytest --tb native -vv -s $(PROJECT)/tests $(ARGS)
	uv run --no-managed-python --all-extras coverage report
