from distutils.core import setup
import sys
from importlib.machinery import SourceFileLoader

check_docker = SourceFileLoader('check_docker', './check_docker').load_module()


if sys.version_info < (3, ):
    raise SystemExit('check_docker requires Python 3.3 or higher.')

setup(
    name="check_docker",
    version=check_docker.__version__,
    description="NRPE plugin for monitoring Docker containers and swarms",
    author="Tim Laurence",
    author_email="timdaman@gmail.com",
    url="https://github.com/timdaman/check_docker",
    keywords=["nrpe", "nagios", "docker", "monitoring"],
    scripts=["check_docker", "check_swarm"],
    download_url="https://github.com/timdaman/check_docker/archive/master.zip",
    python_requires=">=3.0",
    classifiers=[
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Intended Audience :: System Administrators",
        "Environment :: Other Environment",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
        "Topic :: System :: Networking",
        ],
    long_description=open('README.txt').read(),
)
