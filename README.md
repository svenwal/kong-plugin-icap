# kong-plugin-icap
Virus scanner plugin for Kong APIGateway leveraging ICAP protocol

## Configuration 
The plugin can be added to a route with the following request to the Kong Admin endpoint. 
```
$ curl -X POST http://kong:8001/apis/{route}/plugins \
    --data "name=kong-plugin-icap" \
    --data "config.icap_host=host.ip.of.icap.server" \
    --data "config.icap_port={port number of icap server} \
    --data "config.icap_service=icap://{icap host ip}:{icap port}/{name of icap service}" \
    --data "config.timeout=TIMEOUT_DURATION" \
    --data "config.keepalive=KEEPALIVE_DURATION" \
    --data "config.content_to_scan=text/plain, application/pdf, etc." \
    --data "config.tls={true or false}" \
    --data "config.tls_sni={server name indicator}
```

| Form Parameter | required | default | description |
| -------------- | -------- | ------- | ----------- |
| `name`         | yes      |         | plugin name `kong-plugin-icap`|
| `config.icap_host`    | yes      |         | the host ip that the icap server is running on |
| `config.icap_port`    | yes      |         | the port number that the icap server is running on |
| `config.icap_service` | yes      |         | the service name that will conduct virus scanning on the side of icap. Note, the formatting convention shown in the example above is standard for icap services |
| `config.timeout`      | no       | 10000   | sets the upper timeout limit for making a socket tcp connection to the icap server in milliseconds. By default, this field indicates that requests taking more than 10 seconds will timeout. |
| `config.keepalive`    | no       | 120000  | sets the upper keepalive limit for creating a new socket connection to the icap server in milliseconds. By default, this field will allow open socket connections to be added to a connection pool and reused for up to two minutes. |
| `config.content_to_scan`| yes    | "text/plain", "multipart/form-data", "application/x-www-form-urlencoded", "application/pdf", "application/zip", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "application/vnd.ms-excel", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "application/msword", "application/octet-stream"   | whitelist of `content-types` that will be accepted to scan. If a `content-type` is detected and not on the whitelist, a `415 Unsupported Media Type` status code will be returned back to the client. Note, if a `content-type` is desired to be scanned *in addition* to what is whitelisted, all whitelisted `content-types` will need to be redefined in this field |
| `config.tls`          | no       | false    | boolean value indicating whether or not tls is enabled with the icap server. If it is, a TLS handshake will be performed. |
| `congif.tls_sni`      | no       | if the `config.tls` parameter is enabled, this field must be defined in order to perform the TLS handshake with the icap server. |


## Supported Kong Releases
Kong >= 1.0

## Installation
Recommended: 
```
$ luarocks install kong-plugin-auth
```
NOTE, not yet pushed to luarocks - update this doc when completed

Other: 
```
$ git clone https://github.com/Optum/kong-plugin-icap.git /path/to/kong/plugins/kong-plugin-icap
$ cd /path/to/kong/plugins/kong-plugin-icap
$ luarocks make *.rockspec
```
## DB less mode 
This plugin can also be configured with a declarative config yaml file. See the following example. 

### kong.yml
```
_format_version: "1.1"

services:
- name: example-service
  url: {some_service_url.com}
  tags:
  - example
  routes:
  - name: vscanning
    paths: 
    - /vs

plugins:
- name: kong-plugin-icap
  config:
    icap_host: {"icap.ip.address"}
    icap_port: {port#}
    icap_service: "icap://{icap_host}:{icap_port}/{name_of_icap_service}"

    timeout: 10000
    keepalive: 120000

    content_to_scan: ["multipart/form-data", 
    "application/x-www-form-urlencoded", 
    "application/pdf", 
    "application/zip", 
    "text/plain", 
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", 
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.ms-excel",
    "application/msword"]  

    tls: false 
    tls_sni: {"tls_server_name_indicator"}
```
Also needed is a `kong.conf` file 

### kong.conf
```
proxy_listen=0.0.0.0:8080
proxy_error_log=/dev/stderr
admin_error_log=/dev/stderr
database=off
declarative_config=/{location/of/kong.yml}

plugins=bundled,kong-plugin-icap
# this optional config field defines the max payload size
nginx_http_client_body_buffer_size = 50M 
```

Navigate to the running instance of kong and run the following:

```
cd {location of the directory with kong.conf file within kong}
kong start -c kong.conf
```

For further details on declarative configs in Kong reference [this](https://docs.konghq.com/gateway-oss/2.3.x/db-less-and-declarative-config/)

## Maintainers 

[AntonyGor](https://github.com/AntonyGor)

Feel free topen issues, or refer to the [Contribution Gidelines](./CONTRIBUTING.md) if you have any questions. 