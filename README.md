# Vault Plugin: Exoscale Auth Method

[![Actions Status](https://github.com/exoscale/vault-plugin-auth-exoscale/workflows/CI/badge.svg?branch=master)](https://github.com/exoscale/vault-plugin-auth-exoscale/actions?query=workflow%3ACI+branch%3Amaster)

This is a [backend plugin][vault-doc-plugins] plugin to be used with HashiCorp [Vault](https://www.vaultproject.io/). This plugin authenticates Vault clients based on Exoscale Compute instance properties.

This guide assumes you have already installed Vault and have a basic understanding of how Vault works. Otherwise, first read this guide on how to [get started with Vault][vaultdocintro].

**Please note**: If you believe you have found a security issue in this plugin, _please responsibly disclose_ by contacting us at [security@exoscale.com](mailto:security@exoscale.com) instead of opening an issue at GitHub.


## Quick Links

- [Vault Website](https://www.vaultproject.io)
- [Exoscale](https://www.exoscale.com/)


## Installation

### Using pre-built releases (recommended)

You can find pre-built releases of the plugin [here][gh-releases]. Once you have downloaded the latest archive corresponding to your target OS, uncompress it to retrieve the `vault-plugin-auth-exoscale` plugin binary file.


### From Sources

If you prefer to build the plugin from sources, clone the GitHub repository locally and run the command `make build` from the root of the sources directory. Upon successful compilation, the resulting `vault-plugin-auth-exoscale` binary is stored in the `bin/` directory.


## Configuration

Copy the plugin binary into a location of your choice; this directory must be specified as the [`plugin_directory`][vault-doc-plugin-dir] in the Vault configuration file:

```hcl
plugin_directory = "path/to/plugin/directory"
```

Start a Vault server with this configuration file:

```sh
$ vault server -config=path/to/vault/config.hcl
```

Once the server is started, register the plugin in the Vault server's [plugin catalog][vault-doc-plugin-catalog]:

```sh
$ vault plugin register \
    -command="vault-plugin-auth-exoscale" \
    -sha256="$(sha256sum path/to/plugin/directory/vault-plugin-auth-exoscale | cut -d " " -f 1)" \
    auth exoscale
```

You can now enable the `exoscale` auth method:

```sh
$ vault auth enable exoscale
```


## Usage

### Auth Backend Configuration

In order to be able to authenticate Vault clients from Exoscale, the backend must be configured with Exoscale API credentials beforehand:

```sh
$ vault write auth/exoscale/config \
    api_key=$EXOSCALE_API_KEY \
    api_secret=$EXOSCALE_API_SECRET
```


### Backend Roles

Backend roles are used to determine how Vault clients running on Exoscale Compute instances must be authenticated by the exoscale auth method.

When creating a role, the following checks (disabled by default) can be performed:

* The specified Compute instance must be member of a specific [Instance Pool][exo-doc-instance-pools].
* The client (requester) IP address must match the specified Compute instance's IP address.
* The specified Compute instance must not have been created too long ago.

```sh
$ vault write auth/exoscale/role/ci-worker \
    token_policies=ci-worker \
    allowed_instance_pools=6d540f20-ac97-dd6a-5d67-cc11a5e224a5
```

Besides additional checks configuration, roles can also be used to set the properties of the Vault [tokens][vault-doc-tokens] to be issued upon successful authentication: run the `vault path-help auth/exoscale/role/create` for more information.


### Log into Vault using the Exoscale auth method

Clients wishing to log into a Vault server to retrieve a token must specify the zone and ID of the Compute instance they are running on, as well as the name of the desired backend *role*:

```sh
$ vault write auth/exoscale/login \
    role=ci-worker \
    instance=6d540f20-ac97-dd6a-5d67-cc11a5e224a5 \
    zone=de-muc-1
Key                  Value
---                  -----
token                s.brmD5tCpa8ea6RoKF9O9NCOP
token_accessor       V1rfN2q8f7q6AvCZS6HG4Sfs
token_duration       768h
token_renewable      true
token_policies       ["ci-worker" "default"]
identity_policies    []
policies             ["ci-worker" "default"]
```


### Documentation

The complete backend plugin usage documentation is available through the command `vault path-help auth/exoscale`.


[exo-doc-instance-pools]: https://community.exoscale.com/documentation/compute/instance-pools/
[gh-releases]: https://github.com/exoscale/vault-plugin-auth-exoscale/releases
[vault-doc-intro]: https://www.vaultproject.io/intro/getting-started/install.html
[vault-doc-plugin-catalog]: https://www.vaultproject.io/docs/internals/plugins.html#plugin-catalog
[vault-doc-plugin-dir]: https://www.vaultproject.io/docs/configuration/index.html#plugin_directory
[vault-doc-plugins]: https://www.vaultproject.io/docs/internals/plugins.html
[vault-doc-tokens]: https://www.vaultproject.io/docs/concepts/tokens
