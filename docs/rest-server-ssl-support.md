# SSM REST server SSL support

## Configuration options

| Option                                  | Default value | Description                                                                         |
|-----------------------------------------|---------------|-------------------------------------------------------------------------------------|
| smart.rest.server.ssl.enabled           | false         | Whether to enable SSL support for the SSM REST server                               |
| smart.rest.server.ssl.keystore          | -             | The path to the key store that holds the SSL certificate (`JKS` or `PKCS12` format) |
| smart.rest.server.ssl.keystore.password | -             | The password used to access the key store                                           |
| smart.rest.server.ssl.key.alias         | -             | The alias that identifies the key in the key store                                  |
| smart.rest.server.ssl.key.password      | -             | The password used to access the key in the key store                                |
