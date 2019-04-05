.DELETE_ON_ERROR:

all:
	echo >&2 "Must specify target."

test:
	tox

venv:
	tox -evenv

install-hooks:
	tox -e pre-commit -- install -f --install-hooks

clean:
	rm -rf build/ dist/ osxcollector_output_filters.egg-info/ .tox/ virtualenv_run/
	find . -name '*.pyc' -delete
	find . -name '__pycache__' -delete

.PHONY: all test venv install-hooks clean
