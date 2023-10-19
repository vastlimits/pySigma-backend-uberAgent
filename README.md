



# pySigma uberAgent Backend

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
To run the unit tests execute the following command:
- `poetry run pytest --cov=sigma --cov-report term --cov-report xml:cov.xml -vv`

# Development

Add updated version of this backend to local poetry package manager:

- `poetry add ..\vastlimits\pySigma-backend-uberAgent\dist\pysigma_backend_uberagent-0.3.7.tar.gz`

Converting rules:

```
sigma convert -s -f conf -p uberagent -t uberagent "D:\Github\sigma\rules\windows\process_creation\" > process_creation.conf
sigma convert -s -f conf -p uberagent -t uberagent "D:\Github\sigma\rules\windows\image_load\" > image_load.conf
sigma convert -s -f conf -p uberagent -t uberagent "D:\Github\sigma\rules\windows\dns_query\" > dns_query.conf
sigma convert -s -f conf -p uberagent -t uberagent "D:\Github\sigma\rules\windows\network_connection\" > network_connection.conf
sigma convert -s -f conf -p uberagent -t uberagent "D:\Github\sigma\rules\windows\driver_load\" > driver_load.conf
sigma convert -s -f conf -p uberagent -t uberagent "D:\Github\sigma\rules\windows\create_remote_thread\" > create_remote_thread.conf
sigma convert -s -f conf -p uberagent -t uberagent "D:\Github\sigma\rules\windows\process_tampering\" > process_tampering.conf
sigma convert -s -f conf -p uberagent -t uberagent "D:\Github\sigma\rules\windows\file\" > file.conf
sigma convert -s -f conf -p uberagent -t uberagent "D:\Github\sigma\rules\windows\registry\" > registry.conf




sigma convert -s -f conf -p uberagent -t uberagent "D:\Github\sigma\rules\windows\pipe_created\" > pipe_created.conf
sigma convert -s -f conf -p uberagent -t uberagent "D:\Github\sigma\rules\windows\powershell\" > powershell.conf
sigma convert -s -f conf -p uberagent -t uberagent "D:\Github\sigma\rules\windows\process_access\" > process_access.conf
sigma convert -s -f conf -p uberagent -t uberagent "D:\Github\sigma\rules\windows\raw_access_thread\" > raw_access_thread.conf
sigma convert -s -f conf -p uberagent -t uberagent "D:\Github\sigma\rules\windows\sysmon\" > sysmon.conf
sigma convert -s -f conf -p uberagent -t uberagent "D:\Github\sigma\rules\windows\wmi_event\" > wmi_event.conf

```
