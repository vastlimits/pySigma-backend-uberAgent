![Tests](https://github.com/vastlimits/pySigma-backend-uberAgent/actions/workflows/test.yml/badge.svg)
![Coverage Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/svnscha/771a36a467fe196af4b6c9635ff1a12a/raw/vastlimits-pySigma-backend-uberAgent.json)
![Status](https://img.shields.io/badge/Status-pre--release-orange)

# pySigma uberAgent Backend

This is the uAQL backend for pySigma. It provides the package `sigma.backends.uberAgent` with the `uberAgentBackend` class.
Further, it contains the following processing pipelines in `sigma.pipelines.uberAgent`:

* uberagent: Compatible with the latest released uberAgent version.
* uberagent-6.0.0: Compatible with uberAgent 6.0.0 events and properties.
* uberagent-6.1.0: Compatible with uberAgent 6.1.0 events and properties.
* uberagent-6.2.0: Compatible with uberAgent 6.2.0 events and properties.
* uberagent-7.0.0: Compatible with uberAgent 7.0.0 events and properties.
* uberagent-7.1.0: Compatible with uberAgent 7.1.0 events and properties.
* uberagent-7.2.0: Compatible with uberAgent 7.2.0 events and properties.
* uberagent-7.3.0: Compatible with uberAgent 7.3.0 events and properties.
* uberagent-7.4.0: Compatible with uberAgent 7.4.0 events and properties.
* uberagent-develop: Compatible with the upcoming uberAgent version.

It supports the following output formats:

* default: Generates plain uAQL queries.
* conf: Generates `[ThreatDetectionRule]` configuration blocks.

This backend is currently maintained by:

* [vast limits GmbH](https://github.com/vastlimits/)

# Usage
This backend provides integration with the  [sigma-cli](https://github.com/SigmaHQ/sigma-cli) toolkit.
While the sigma-cli's official documentation offers a comprehensive understanding of its functionalities, this guide specifically focuses on its usage in conjunction with the uberAgent backend.

Install the uberAgent backend:

```
poetry add pySigma-backend-uberAgent
```

Verify installation with:

```
sigma list pipelines
+-------------------+----------+---------------------+-----------+
| Identifier        | Priority | Processing Pipeline | Backends  |
+-------------------+----------+---------------------+-----------+
| uberagent-7.1.0   | 20       | uberAgent 7.1.0     | uberagent |
| uberagent-7.2.0   | 20       | uberAgent 7.2.0     | uberagent |
| uberagent-7.3.0   | 20       | uberAgent 7.3.0     | uberagent |
| uberagent-7.4.0   | 20       | uberAgent 7.4.0     | uberagent |
| uberagent-7.5.0   | 20       | uberAgent 7.5.0     | uberagent |
| uberagent-develop | 20       | uberAgent develop   | uberagent |
+-------------------+----------+---------------------+-----------+
```

## Usage Examples

### Converting to the latest uberAgent version
To translate the `process_creation` rules for the most recent version of uberAgent, use the following command:

```
sigma convert -s -f conf -p uberagent -t uberagent "..\sigma\rules\windows\process_creation\" > process_creation.conf
```

Here,
- `-f conf` specifies the output format as configuration blocks.
- `-p uberagent` ensures the compatibility to the latest uberAgent version.

### Targeting older uberAgent versions
If you aim to support a prior version of uberAgent, specify the desired version in the pipeline.

For instance:

```
sigma convert -s -f conf -p uberagent-7.0.0 -t uberagent "..\sigma\rules\windows\process_creation\" > process_creation.conf
```

This command will generate configurations compatible with uberAgent version 7.0.0, rather than the most recent release.

## Streamlined Usage Guide
Once the environment for sigma-cli and pySigma-uberAgent-backend is set up, you can leverage utility scripts to streamline the rule generation process.

### Default Rule Generation
Execute the following commands to copy and convert the Sigma rules for the current released uberAgent version:

```
cd pySigma-backend-uberAgent
mkdir build
cd build
../copy-rules.py "/path/to/sigma/rules"
../convert-rules.sh $(pwd)
```

### Specifying uberAgent Version
To generate rules for a specific version of uberAgent, like uberAgent 6.0.0, follow these steps:

```
cd pySigma-backend-uberAgent
mkdir build
cd build
../copy-rules.py "/path/to/sigma/rules"
../convert-rules.sh $(pwd) uberagent-7.5.0
```


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
