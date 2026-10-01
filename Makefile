.PHONY: install test lint demo serve validate docker
install:  ; python -m pip install -r requirements-dev.txt
test:     ; python -m pytest -q
lint:     ; ruff check lodestar tests
demo:     ; python -m lodestar demo
serve:    ; python -m lodestar serve
validate: ; python -m lodestar validate
docker:   ; docker build -t lodestar:1.2.1 .
