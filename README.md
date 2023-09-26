



# pySigma uAQL Backend

This is the uAQL backend for pySigma. It provides the package `sigma.backends.uberAgent` with the `uberAgentBackend` class.
Further, it contains the following processing pipelines in `sigma.pipelines.uberAgent`:

* pipeline1: purpose
* pipeline2: purpose

It supports the following output formats:

* default: plain uAQL queries
* format_1: purpose
* format_2: purpose

This backend is currently maintained by:

* [vast limits GmbH](https://github.com/vastlimits/)

# Tests

https://github.com/orgs/python-poetry/discussions/1135

poetry run pytest --cov=sigma --cov-report term --cov-report xml:cov.xml -vv
