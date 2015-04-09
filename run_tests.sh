#!/bin/bash

# TODO: make tox install the correct version of neutron so we can run tox
#       instead of these commands manually
nosetests --exclude=mysql
nosetests --where=quark/tests/functional/mysql
nosetests --exclude=mysql --cover-package=quark --cover-erase
flake8 --show-source --builtins=_ quark
