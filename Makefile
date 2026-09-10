.PHONY: setup install test run tui doctor lint bundle clean

setup:            ## install deps into .venv via uv
	uv sync --extra dev

install: setup    ## + put `ronin` on PATH (~/.local/bin symlink)
	scripts/install-cli.sh

test:             ## run the test suite
	uv run pytest -q

run tui:          ## launch the TUI
	uv run ronin

doctor:           ## show toolchain status
	uv run ronin doctor

lint:             ## byte-compile check
	uv run python -m compileall -q ronin

bundle:           ## copy a runnable RoninSuite onto a stick: make bundle DEST=/run/media/you/STICK
	@test -n "$(DEST)" || (echo "set DEST=/path/to/stick" && exit 1)
	scripts/make-usb.sh "$(DEST)"

clean:
	rm -rf .venv .cache .pytest_cache **/__pycache__
