PROJECT := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
SRC := $(PROJECT)src

export UV_PROJECT = $(SRC)
export PYTHONPATH = $(PROJECT):$(SRC)


fmt:
	uv run --all-extras ruff check --fix $(PROJECT)
	uv tool run ruff format $(PROJECT)

lint:
	uv tool run ruff check $(SRC)
	uv tool run ruff format --check --diff $(SRC)
	uv run --extra dev pyright $(SRC)


unit:
	uv run --isolated --all-extras coverage run --source=$(PROJECT)/tests -m pytest --tb native -v -s $(PROJECT)/tests $(ARGS)
	uv run --all-extras coverage report