# SSM REST server authentication methods

To enable REST server authentication, users need to set the `smart.rest.server.security.enabled` option to `true`
and enable at least one authentication provider from the list below. Authentication will be successful if
it is successful in at least one of the authentication providers.

## Predefined users authentication provider

This authentication method simply checks whether the incoming credentials
match any of the predefined users specified in the corresponding option.

### Options

| Name                                               | Default | Description                                                                                                                                                                                                                                                                                            |
|----------------------------------------------------|---------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| smart.rest.server.auth.predefined.enabled          | false   | Whether to enable SSM REST server basic authentication with predefined users                                                                                                                                                                                                                           |
| smart.rest.server.auth.predefined.users            | -       | Comma-separated list of predefined user credentials in the form of `user:password` or `user:{encoderId}password_hash` or `user:password_hash`. In the latter case, the encoder from the `smart.rest.server.auth.predefined.password.encoder` option will be used to verify the incoming user password. |
| smart.rest.server.auth.predefined.password.encoder | noop    | Default encoder for predefined users passwords in case if password doesn't have `{encoderId}` prefix. Possible values: `noop` (for plaintext passwords), `bcrypt`, `ldap`, `md4`, `md5`, `pbkdf2`, `scrypt`, `sha-1`, `sha-256`                                                                        |

## Kerberos basic authentication provider

This authentication method sends SSM user credentials directly to the Kerberos KDC.
The Kerberos client configuration file with KDC url, default realm, etc. should be located
at `/etc/krb5.conf` on the machine where the SSM server is running.
Or you can pass its location as a JVM property when starting the SSM
server: `-Djava.security.krb5.conf=*customKrb5ConfPath*`

### Options

| Name                                    | Default | Description                                                                    |
|-----------------------------------------|---------|--------------------------------------------------------------------------------|
| smart.rest.server.auth.kerberos.enabled | false   | Whether to enable SSM REST server basic Kerberos authentication method support |

## Kerberos SPNEGO authentication provider

This authentication method accepts SPNEGO tokens (which include Kerberos Service Tickets) from a client
and authenticates user if the Service Ticket verification is successful.

### Options

| Name                                    | Default | Description                                                                                         |
|-----------------------------------------|---------|-----------------------------------------------------------------------------------------------------|
| smart.rest.server.auth.spnego.enabled   | false   | Whether to enable SSM REST server Kerberos SPNEGO authentication method support                     |
| smart.rest.server.auth.spnego.principal | -       | Kerberos service principal name for SSM REST server                                                 |
| smart.rest.server.auth.spnego.keytab    | -       | SSM principal keytab. If it's empty the value of the `smart.server.keytab.file` option will be used |

## LDAP authentication provider

### Common options

| Name                                                      | Default      | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
|-----------------------------------------------------------|--------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| smart.rest.server.auth.ldap.enabled                       | false        | Whether to enable SSM REST server basic LDAP authentication method support                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| smart.rest.server.auth.ldap.url                           | -            | Comma-separated list of LDAP server URLs                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| smart.rest.server.auth.ldap.search.base                   | -            | Base LDAP distinguished name for search                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| smart.rest.server.auth.ldap.user.search.base              | -            | Base LDAP distinguished name for user search                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| smart.rest.server.auth.ldap.group.search.base             | -            | Base LDAP distinguished name for group search                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| smart.rest.server.auth.ldap.auth.type                     | BIND         | LDAP authentication type. Possible values: <br/> `BIND`: search user by specified filters and authenticate with found user's DN and provided password <br/> `PASSWORD_COMPARE`: search user by specified filters and use LDAP password compare operation. If user passwords are hashed and don't contain prefix with hashing algorithm (in form of `{encoderId}`), user should provide encoder name in the `smart.rest.server.auth.ldap.password.encoder` option or configure encoded password matching rules on the LDAP server side. |
| smart.rest.server.auth.ldap.bind.user                     | -            | Distinguished name of the user for initial (service) connection to the LDAP server                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| smart.rest.server.auth.ldap.bind.password                 | -            | Password of the user for initial (service) connection to the LDAP server                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| smart.rest.server.auth.ldap.user.attributes.password      | userPassword | The password attribute of user LDAP object                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| smart.rest.server.auth.ldap.user.search.additional.filter | -            | Additional LDAP filter, that will be added to all user search LDAP queries                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| smart.rest.server.auth.ldap.user.search.scope             | ONE_LEVEL    | The scope of LDAP user search. Possible values: `OBJECT` - Search the named object <br/> `ONE_LEVEL` - Search one level of the named context <br/> `SUBTREE` - Search the entire subtree rooted at the named object                                                                                                                                                                                                                                                                                                                    |
| smart.rest.server.auth.ldap.group.search.scope            | ONE_LEVEL    | The scope of LDAP group search. Possible values: `OBJECT` - Search the named object <br/> `ONE_LEVEL` - Search one level of the named context <br/> `SUBTREE` - Search the entire subtree rooted at the named object                                                                                                                                                                                                                                                                                                                   |
| smart.rest.server.auth.ldap.password.encoder              | noop         | Default encoder for LDAP users passwords in case if password doesn't have `{encoderId}` prefix. Possible values: `noop` (for plaintext passwords), `bcrypt`, `ldap`, `md4`, `md5`, `pbkdf2`, `scrypt`, `sha-1`, `sha-256`                                                                                                                                                                                                                                                                                                              |

User authentication can be done using one of several strategies.
A strategy is selected if all the required trigger options are provided.
If a user provides options for more than one strategy, only the highest priority one will be used.
The strategies are listed in descending order of priority, from highest to lowest.

### Custom query strategy

**Trigger options**: `smart.rest.server.auth.ldap.user.search.filter`

If any entry is found during the search using the provided LDAP filter, SSM user will be authenticated.

Supported options:

| Name                                           | Default | Description                                                              |
|------------------------------------------------|---------|--------------------------------------------------------------------------|
| smart.rest.server.auth.ldap.user.search.filter | -       | Custom LDAP query, that will be used to find the user for authentication |

### User membership attribute strategy

**Trigger options**: `smart.rest.server.auth.ldap.user.attributes.membership`
and `smart.rest.server.auth.ldap.user.search.groups`

1. Fetch DNs of groups (entry with `objectClass` equal to the value of the corresponding option) with the name
   attribute (can be configured) equal to any value of the `smart.rest.server.auth.ldap.user.search.groups` option
2. Check is there any user (entry with `objectClass` equal to any value of the corresponding option) with the
   membership attribute (can be configured) equal to any of the groups DNs from
   previous step, and
   with name attribute (can be configured) equal to SSM username
   If a user entry and any group entry exist, SSM user will be authenticated.

Supported options:

| Name                                                   | Default      | Description                                                                                    |
|--------------------------------------------------------|--------------|------------------------------------------------------------------------------------------------|
| smart.rest.server.auth.ldap.user.attributes.name       | uid          | The name attribute of user LDAP object                                                         |
| smart.rest.server.auth.ldap.user.object-classes        | person       | Comma-separated list of LDAP user entry objectClasses                                          |
| smart.rest.server.auth.ldap.user.attributes.membership | memberOf     | The group membership attribute of user LDAP object                                             |
| smart.rest.server.auth.ldap.group.object-class         | groupOfNames | LDAP group entry objectClass                                                                   |
| smart.rest.server.auth.ldap.group.attributes.name      | cn           | The name attribute of group LDAP object                                                        |
| smart.rest.server.auth.ldap.user.search.groups         | -            | Comma-separated list of groups the user should belong to in order to successfully authenticate |

### Group member attribute strategy

**Trigger options**: `smart.rest.server.auth.ldap.group.attributes.member`
and `smart.rest.server.auth.ldap.user.search.groups`

1. Fetch DN of user (entry with `objectClass` equal to any value of the corresponding option) with
   name attribute (can be configured) equal to SSM username
2. Check are there any group (entry with `objectClass` equal to the value of the corresponding option) with the
   name attribute (can be configured) equal to any value of
   the `ldap.user.search.groups` option with
   member attribute (can be configured) equal to user DN from previous step.
   If a user entry and any group entry exist, SSM user will be authenticated.

Supported options:

| Name                                                | Default      | Description                                                                                    |
|-----------------------------------------------------|--------------|------------------------------------------------------------------------------------------------|
| smart.rest.server.auth.ldap.user.attributes.name    | uid          | The name attribute of user LDAP object                                                         |
| smart.rest.server.auth.ldap.user.object-classes     | person       | Comma-separated list of LDAP user entry objectClasses                                          |
| smart.rest.server.auth.ldap.group.object-class      | groupOfNames | LDAP group entry objectClass                                                                   |
| smart.rest.server.auth.ldap.group.attributes.name   | cn           | The name attribute of group LDAP object                                                        |
| smart.rest.server.auth.ldap.group.attributes.member | member       | The member attribute of group LDAP object                                                      |
| smart.rest.server.auth.ldap.user.search.groups      | -            | Comma-separated list of groups the user should belong to in order to successfully authenticate |

### User name attribute strategy

Check is there any user (entry with `objectClass` equal to any value of the corresponding option) with
name attribute (can be configured) equal to SSM username.
If any user entry exists, SSM user will be authenticated.

Supported options:

| Name                                             | Default | Description                                           |
|--------------------------------------------------|---------|-------------------------------------------------------|
| smart.rest.server.auth.ldap.user.attributes.name | uid     | The name attribute of user LDAP object                |
| smart.rest.server.auth.ldap.user.object-classes  | person  | Comma-separated list of LDAP user entry objectClasses |

