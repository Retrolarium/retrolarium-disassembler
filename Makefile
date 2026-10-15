# Checks before a commit. `make hooks` once per clone makes Git run them on
# every commit and push (retrolarium_core.hooks): the stop words in the staged
# changes, the commit message and what a push sends, then `make lint` and
# `make format-check`. The stop-word list lives outside the repositories, in
# a .stopwords file above this one (see retrolarium_core/stop_words.py).

PYTHON ?= python
CORE ?= ../retrolarium-core/python/retrolarium_core

.PHONY: lint format format-check hooks

# Stop words in the files Git tracks, their contents and their paths.
lint:
	$(PYTHON) $(CORE)/stop_words.py check .

# Markdown through mdformat with the mdformat-gfm plugin (.mdformat.toml).
format:
	$(PYTHON) $(CORE)/hooks.py markdown .

format-check:
	$(PYTHON) $(CORE)/hooks.py markdown . --check

hooks:
	$(PYTHON) $(CORE)/hooks.py install .
