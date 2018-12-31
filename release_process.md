
1. Confirm documentation is updated
    - README
    - DEV doc
1. Unit tests pass
1. Isolated tests pass

        ./run_isolated_tests.sh

1. make package

        poetry build

1. Uninstall check_docker and install package

        pipenv uninstall check_docker && pipenv run flit install --format sdist

1. Bats smoke tests pass

        ./run_package_tests.sh
  
1. Push to branch
1. Confirm doc looks good on github
1. Travis tests pass
1. Create and merge PR
1. Confirm Travis still passes
1. CodeClimate does not show scary issues (need to modify analyzed branch)
1. Upload package to test repo

       poetry publish -r pypi -u timdaman -p xxxx

1. Check test project page for formatting

   https://test.pypi.org/project/check_docker/

1. Upload package to prod repo

        poetry publish -r prodpypi -u timdaman -p xxxx

1. Check project page for formatting

   https://pypi.org/project/check_docker/
