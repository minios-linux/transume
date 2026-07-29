PYTHON ?= python3

.PHONY: all test check i18n-compile i18n-check gtk-smoke gtk-qualification clean

all: check

test:
	$(PYTHON) -m pytest -q

check: test
	@if command -v desktop-file-validate >/dev/null 2>&1; then desktop-file-validate data/dev.minios.transume.desktop; else echo "desktop-file-validate not installed; skipping"; fi
	@if command -v xmllint >/dev/null 2>&1; then xmllint --noout data/polkit/dev.minios.transume.policy; else echo "xmllint not installed; skipping"; fi
	@if command -v appstreamcli >/dev/null 2>&1; then appstreamcli validate --no-net data/dev.minios.transume.metainfo.xml; else echo "appstreamcli not installed; skipping"; fi

i18n-compile:
	@for po in po/*.po; do \
		lang=$$(basename "$$po" .po); \
		dir="locale/$$lang/LC_MESSAGES"; \
		mkdir -p "$$dir"; \
		msgfmt --check --output-file="$$dir/transume.mo" "$$po" || exit 1; \
	done

i18n-check:
	@for po in po/*.po; do msgfmt --check --output-file=/dev/null "$$po" || exit 1; done

gtk-smoke:
	xvfb-run -a $(PYTHON) tools/gtk_click_smoke.py

# Each invocation starts at one exact size, avoiding WM resize races between cases.
gtk-qualification:
	xvfb-run -a $(PYTHON) tools/gtk_click_smoke.py --geometry 800x520
	xvfb-run -a $(PYTHON) tools/gtk_click_smoke.py --geometry 1024x600
	xvfb-run -a $(PYTHON) tools/gtk_click_smoke.py --geometry 1180x640 --dark
	xvfb-run -a env GDK_SCALE=2 $(PYTHON) tools/gtk_click_smoke.py --geometry 1280x800 --font-scale 2 --require-scale 2
	xvfb-run -a $(PYTHON) tools/gtk_click_smoke.py --geometry 1180x640 --high-contrast

clean:
	rm -rf build dist .pytest_cache locale
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
