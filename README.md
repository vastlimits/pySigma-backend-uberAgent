# pySigma uberAgent Backend

This is the uAQL backend for pySigma. It provides the package `sigma.backends.uberAgent` with the `uberAgentBackend` class.
Further, it contains the following processing pipelines in `sigma.pipelines.uberAgent`:

* uberagent: Compatible with the latest released uberAgent version.
* uberagent-6.0.0: Compatible with uberAgent 6.0.0 events and properties.
* uberagent-6.1.0: Compatible with uberAgent 6.1.0 events and properties.
* uberagent-6.2.0: Compatible with uberAgent 6.2.0 events and properties.
* uberagent-7.0.0: Compatible with uberAgent 7.0.0 events and properties.
* uberagent-7.1.0: Compatible with uberAgent 7.1.0 events and properties.
* uberagent-develop: Compatible with the upcoming uberAgent version.

It supports the following output formats:

* default: Generates plain uAQL queries.
* conf: Generates `[ActivityMonitoringRule]` configuration blocks.

This backend is currently maintained by:

* [vast limits GmbH](https://github.com/vastlimits/)

# Usage
This backend provides integration with the  [sigma-cli](https://github.com/SigmaHQ/sigma-cli) toolkit.
While the sigma-cli's official documentation offers a comprehensive understanding of its functionalities, this guide specifically focuses on its usage in conjunction with the uberAgent backend.

Install the uberAgent backend run:
```
sigma plugin install uberagent
```

To list all available plugins run the following command:
```
sigma plugin list
```

The output should list uberAgent as installed backend.

```
+----------------------+----------+---------+--------------------------------------------------------------+-------------+
| Identifier           | Type     | State   | Description                                                  | Compatible? |
+----------------------+----------+---------+--------------------------------------------------------------+-------------+
```

## Usage Examples

### Converting to the latest uberAgent version
To translate the `process_creation` rules for the most recent version of uberAgent, use the following command:

```
sigma convert -s -f conf -p uberagent -t uberagent "D:\Github\sigma\rules\windows\process_creation\" > process_creation.conf
```

Here,
- `-f conf` specifies the output format as configuration blocks.
- `-p uberagent` ensures the compatibility to the latest uberAgent version.

### Targeting older uberAgent versions
If you aim to support a prior version of uberAgent, specify the desired version in the pipeline.

For instance:

```
sigma convert -s -f conf -p uberagent-7.0.0 -t uberagent "D:\Github\sigma\rules\windows\process_creation\" > process_creation.conf
```

This command will generate configurations compatible with uberAgent version 7.0.0, rather than the most recent release.


# Development Guidelines

## Unit Tests
We maintain a rigorous testing regime for this backend through unit tests. As you introduce new features, ensure that you also add corresponding unit tests.

To execute the unit tests, run:

```
poetry run pytest --cov=sigma --cov-report term --cov-report xml:cov.xml -vv
```


## Integration with sigma-cli
When you make updates to this backend, remember to:

1. Increment the version number in `pyproject.toml`
2. Compile the package with:

```
poetry build
```

In the `sigma-cli` environment, incorporate uberAgent as a local backend by using:

```
poetry add ..\pySigma-backend-uberAgent\dist\pysigma_backend_uberagent-X.Y.Z.tar.gz
```

Ensure that you replace **X.Y.Z** with the updated version number and adjust the path to point to the built package location.
