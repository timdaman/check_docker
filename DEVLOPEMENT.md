# Development environment setup

You should have the following installed

- docker
- pytest
- python (version >= 3.0)
- `pip install -r dev_requirement.txt`

# Running the tests

## Normal tests
Pytest is used for testing. You can can run test by running the following from
the root of the project

    py.test

## Isolated tests
Sometimes test cases can interact with Docker on the development machine making
it hard to determine the cuase of a test success or failure. To address this
you can use the `run_isolated_tests.sh` script to run pytest inside a
environment isolated from any netwwork. Additionally this isolated test will
run the unit tests on multiple versions of python so you can validate your
changes are not python version specific.

    ./run_isolated_tests.sh

# Coverage report
The aim is to keep coverage above 90% on the actually checks
(check_docker.py and check_swarm.py). To generate a coverage report.

    py.test --cov=check_docker/

# Tips
When jumping back and forth between normal and isolated tests the `__pycache__`
directories can fall out fo sync with your execution environment. When this
happens you see errors like `ImportError: No module named 'check_docker'. The
fix is simple, just remove all the `__pycache__` directories in the project.