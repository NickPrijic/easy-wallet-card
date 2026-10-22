PYTHON ?= python3

.PHONY: test mutation

test:
	$(PYTHON) -m unittest discover -s tests -v

mutation:
	tests/mutation_check.sh
