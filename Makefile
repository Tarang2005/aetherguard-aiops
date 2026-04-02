.PHONY: install dev api dashboard demo test lint chaos clean

# ── Setup ─────────────────────────────────────────────────────────────────────

install:
	pip install -e ".[dev]"

# ── Development ───────────────────────────────────────────────────────────────

api:
	uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload

dashboard:
	streamlit run frontend/streamlit_app.py

dev:
	@echo "Starting AetherGuard (API + Dashboard)..."
	@make api &
	@sleep 3
	@make dashboard

# ── Demo ──────────────────────────────────────────────────────────────────────

demo:
	@echo "Running AetherGuard demo pipeline..."
	python agents/supervisor.py

chaos:
	@echo "Injecting cpu_spike scenario..."
	curl -X POST http://localhost:8000/api/chaos/inject \
		-H "Content-Type: application/json" \
		-d '{"scenario": "cpu_spike", "run_chaos": true}'

# ── Testing ───────────────────────────────────────────────────────────────────

test:
	pytest tests/ -v --cov=agents --cov=core --cov=backend --cov-report=term-missing

test-unit:
	pytest tests/unit/ -v

test-integration:
	pytest tests/integration/ -v

test-chaos:
	pytest tests/chaos/ -v

# ── Lint ──────────────────────────────────────────────────────────────────────

lint:
	ruff check . --fix
	ruff format .

# ── Docker ────────────────────────────────────────────────────────────────────

docker-up:
	docker-compose up --build

docker-down:
	docker-compose down

# ── Cleanup ───────────────────────────────────────────────────────────────────

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	rm -rf .pytest_cache .ruff_cache htmlcov .coverage