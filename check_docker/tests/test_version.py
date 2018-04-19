import os
from urllib import request
from urllib.error import HTTPError

import pytest

from check_docker import check_swarm, check_docker


def test_versions_match():
    assert check_docker.__version__ == check_swarm.__version__


@pytest.mark.skipif('isolated' in os.environ and os.environ['isolated'].lower != 'false',
                    reason="Can not reach Python packge index when isolated")
def test_package_present():
    req = request.Request("https://pypi.org/project/check_docker/", method="HEAD")
    with request.urlopen(req) as resp:
        assert resp.getcode() == 200


@pytest.mark.xfail('TRAVIS_BRANCH' in os.environ and os.environ['TRAVIS_BRANCH'].lower != 'master',
                    reason="Ignore version check outside of master")
@pytest.mark.skipif('isolated' in os.environ and os.environ['isolated'].lower != 'false',
                    reason="Can not reach Python package index when isolated")
def test_ensure_new_version():
    version = check_docker.__version__
    req = request.Request("https://pypi.org/project/check_docker/{version}/".
                          format(version=version), method="HEAD")

    try:
        with request.urlopen(req) as resp:
            http_code = resp.getcode()
    except HTTPError as e:
        http_code = e.code
    assert http_code == 404, "Version already exists. Ignore this if you are workign on a PR"
