.PHONY: lint test

lint:
	python -m pylint check_docker/
test:
	py.test -v
coverage:
	py.test --cov=check_docker
