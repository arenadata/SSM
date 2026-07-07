# Run Hadoop cluster with SSM in docker containers

There are one currently supported HDFS version:

* 3.4.3

## Singlehost configuration

Not supported currently

## Multihost configuration

* Hadoop datanode container
* Hadoop namenode, node manager, resource manager in container
* SSM Server container
* SSM metastore as postgres container
* Kerberos KDC container
* Samba LDAP server
* Prometheus server

Command to build project with docker images (from project root dir)

```shell
mvn clean install -Pdist,web-ui,hadoop-3.4,withDocker -DskipTests
```

Command to start docker containers

```shell
docker-compose -f supports/tools/docker/multihost/docker-compose.yaml up -d
```

Use one of the following credentials to log in to the Web UI

| Login          | Password      | Type     |
|----------------|---------------|----------|
| john           | 1234          | static   |
| krb_user1@DEMO | krb_pass1     | kerberos |
| krb_user2@DEMO | krb_pass2     | kerberos |
| july           | kitty_cat     | ldap     |
| ben            | bens_password | ldap     |

### SSM Master debug

To enable debugging support for the SSM Master add the `--debugMaster` argument, when executing the `start-demo.sh` script. 
Debugger then can be attached to the `localhost:8008`.

### SSM Agent debug

To enable debugging support for the SSM Agent add the `--debugAgent` argument, when executing the `start-demo.sh` script.
Debugger then can be attached to the `localhost:8009`.

### Testing SPNEGO auth

In order to test SPNEGO authentication provider, you need to:

1. Move the `supports/tools/docker/multihost/kerberos/krb5.conf` Kerberos configuration file to the `/etc` directory
   (after backing up your old config file)
2. Log in to the KDC server with one of the Kerberos principals

```shell
kinit krb_user1
```

3. Add the following lines to the `/etc/hosts` file

```
127.0.0.1       ssm-server.demo
127.0.0.1       kdc-server.demo
```

4. Try to access any SSM resource. Following query should respond with code 200 and json body:

```shell
curl --negotiate http://ssm-server.demo:8081/api/v2/audit/events
```

# Run tests

Run unit tests:

```shell
mvn test -Dmaven.test.redirectTestOutputToFile=false -Phadoop-3.4
```

Run integration tests:

```shell
mvn test -Dmaven.test.redirectTestOutputToFile=false -Pit-tests -f smart-integration/pom.xml
```

Run UI tests:
```shell
mvn verify -Pweb-tests -f smart-tests/pom.xml
```

Run HMS tests suite:
```shell
mvn verify -Phms-tests -f smart-tests/pom.xml
```

Web tests can be launched in 2 modes - `docker` or `remote`, it can be specified in the `general.env-type` test property.
- `docker` mode means that SSM starts locally in docker containers and shut down after tests are finished. **Used by default.**
- `remote` mode requires already started SSM cluster to run tests.

Also, web tests can be launched in different grids or in local browser. It can be specified in the `general.browser-manager` test property.
- `local` - local Chrome browser is used.
- `selenoid` - Selenoid starts locally in docker containers.
- `moon` - remote Moon cluster is used.

Configuration values can be changed either directly in application.yml config or by passing env variables (`ENV_TYPE` and `BROWSER_MANAGER`) in TestNG run configuration.

In case of running UI tests in Moon against test environment deployed on your local machine, reverse ssh tunnel is set up automatically (because developer's machines are not accessible from cloud directly).
For proper work you must provide your personal secrets via env variables (SSH_TUNNEL_USERNAME, SSH_TUNNEL_KEY_PATH, SSH_TUNNEL_KEY_PASSPHRASE) and make sure the ssh user is created on remote server used for tcp forwarding.
