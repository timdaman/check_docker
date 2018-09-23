
1. Confirm documentation is updated
    - README
    - DEV doc
1. Unit tests pass
1. Isolated tests pass

        ./run_isolated_tests.sh
1. make package

        python setup.py sdist
1. Uninstall check_docker and install package

        pip uninstall check_docker &&  pip install dist/check_docker-2.0.X.tar.gz
1. Bats smoke tests pass

        ./run_package_tests.sh
1. Push to branch
1. Confirm doc looks good on github
1. Travis tests pass
1. Create and merge PR
1. Confirm Travis still passes
1. CodeClimate doesn't show scary issues (need to modify analyized branch)
1. Upload package to test repo

        twine upload --repository testpypi dist/check_docker-2.0.x.tar.gz
1. Check test project page for formatting

   https://test.pypi.org/project/check_docker/
1. Upload package to prod repo

        twine upload -r pypi dist/check_docker-2.0.x.tar.gz
1. Check project page for formatting

   https://pypi.org/project/check_docker/
