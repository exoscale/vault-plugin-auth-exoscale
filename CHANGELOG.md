# Changelog

## UNRELEASED

### Improvements

- go.mk: remove submodule and initialize through make #12 
- automate release with Exoscale Tooling GPG key #11
- go.mk: lint with staticcheck #13 
- go.mk: upgrade to v2.0.3 #14 

## 0.2.0

### Changes

- Backend configuration now requires an Exoscale zone to be specified (see `vault path-help auth/exoscale/config`)
- Role validation expression variable `instance_tags` has been renamed `instance_labels`
- Role validation expression variable `instance_zone_id` has been removed
- Role validation expression variable `instance_zone_name` has been renamed `instance_zone`
- Path `auth/exoscale/login` doesn't require a `zone` field anymore

### Features

- New role validation expression variable `instance_manager_name`


## 0.1.1

### Bug Fixes

- Fix "500 backend is not configured" error on server restart


## 0.1.0

Initial release
