.PHONY: install test lint demo serve validate doctor docker lock
install:  ; python -m pip install -r requirements-dev.txt
test:     ; python -m pytest -q
lint:     ; ruff check lodestar tests
demo:     ; python -m lodestar demo
serve:    ; python -m lodestar serve
validate: ; python -m lodestar validate
doctor:   ; python -m lodestar doctor
lock:     ; pip-compile -q --strip-extras --no-emit-index-url --output-file requirements.txt requirements.in
docker:   ; docker build -t lodestar:2.2.1 .
