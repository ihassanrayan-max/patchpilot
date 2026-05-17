.PHONY: setup lint typecheck test ingest train eval serve demo up down

setup:
	uv sync

lint:
	uv run ruff check .

typecheck:
	uv run mypy src/patchpilot

test:
	uv run pytest -q

ingest:
	uv run patchpilot ingest --source all

train:
	uv run patchpilot train --config config/settings.toml

eval:
	uv run patchpilot eval --report docs/benchmarks/REPORT.md

serve:
	uv run patchpilot serve --host 0.0.0.0 --port 8000

demo:
	uv run streamlit run apps/demo/streamlit_app.py --server.port 8501 --server.address 0.0.0.0

up:
	docker compose up -d --build

down:
	docker compose down -v
