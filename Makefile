.PHONY: lint test

lint:
	python3 -m pylint check_docker/
test:
	py.test -v
coverage:
	py.test --cov=check_docker
