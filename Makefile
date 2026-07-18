.PHONY: setup lint typecheck test test-e2e ingest train eval ablate serve demo up down

setup:
	uv sync

lint:
	uv run ruff check .

typecheck:
	uv run mypy src/patchpilot

test:
	uv run pytest -q

test-e2e:
	uv run pytest -q tests/test_e2e_fixtures.py tests/test_api.py

ingest:
	uv run patchpilot ingest --source all

train:
	uv run patchpilot train --config config/settings.toml

eval:
	uv run patchpilot eval --report docs/benchmarks/REPORT.md

ablate:
	uv run patchpilot eval --report docs/benchmarks/REPORT.md --ablate

serve:
	uv run patchpilot serve --host 0.0.0.0 --port 8000

demo:
	uv run streamlit run apps/demo/streamlit_app.py --server.port 8501 --server.address 0.0.0.0

up:
	docker compose up -d --build

down:
	docker compose down -v
