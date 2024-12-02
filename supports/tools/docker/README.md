# Run Hadoop cluster with SSM in docker containers

There are two cluster types:

* singlehost
* multihost

And one currently supported HDFS version:

* 3.3.*

## Singlehost configuration

* Hadoop + SSM in one container
* SSM metastore as postgres container

Command to build docker images in singlehost cluster mode (from project root dir)

```shell
./build-images.sh --cluster=singlehost --hadoop=3.3
```

Command to start docker containers

```shell
cd ./supports/tools/docker
./start-demo.sh --cluster=singlehost --hadoop=3.3
```

## Multihost configuration

* Hadoop datanode container
* Hadoop namenode, node manager, resource manager in container
* SSM Server container
* SSM metastore as postgres container
* Kerberos KDC container
* Samba LDAP server
* Prometheus server

Command to build docker images in multihost cluster mode (from project root dir)

```shell
./build-images.sh --cluster=multihost --hadoop=3.3
```

Command to start docker containers

```shell
cd ./supports/tools/docker
./start-demo.sh --cluster=multihost --hadoop=3.3
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
