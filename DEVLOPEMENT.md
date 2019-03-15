# Development environment setup

You should have the following installed

- docker
- python (version >= 3.0)
- pipenv
- vagrant

Initialize your pipenv 

    pipenv install --skip-lock
    
# Running the tests

## Normal tests
tox and Pytest is used for testing. You can can run test by running the following from
the root of the project

    tox

## Isolated tests
Sometimes test cases can interact with Docker on the development machine making
it hard to determine the cause of a test success or failure. To address this
you can use the `run_isolated_tests.sh` script to run pytest inside a
environment isolated from any network. Additionally this isolated test will
run the unit tests on multiple versions of python so you can validate your
changes are not python version specific.

    ./run_isolated_tests.sh

## Package tests
These test verify that, after created, the package can be installed and
runs successfully(not just passes unit tests). To do this a test environment is set up in vagrant.

    ./run_package_tests.sh

# Coverage report
The aim is to keep coverage above 90% on the actual checks
(check_docker.py and check_swarm.py). To generate a coverage report.

    pipenv run py.test --cov=check_docker/

# Tips
When jumping back and forth between normal and isolated tests the `__pycache__`
directories can fall out fo sync with your execution environment. When this
happens you see errors like `ImportError: No module named 'check_docker'. The
fix is simple, just remove all the `__pycache__` directories in the project.