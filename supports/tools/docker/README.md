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

# Run/Test SSM with Docker

Docker can greately reduce boring time for installing and maintaining software on servers and developer machines. This
document presents this basic workflow of Run/test ssm with
docker. [Docker Quick Start](https://docs.docker.com/get-started/)

## Necessary Components

### MetaStore(Postgresql) on Docker

#### Launch a postgresql container

Pull latest postgresql official image from docker store. You can use `postgres:tag` to specify the Postgresql version (
`tag`) you want.

```
docker pull postgres
```

Launch a postgres container with a given {passowrd} on 5432, and create a test database/schema named `{database_name}`.

```bash
docker run -p 5432:5432 --name {container_name} -e POSTGRES_PASSWORD={password} -e POSTGRES_DB={database_name} -d postgres:latest
```

**Parameters:**

- `container_name` name of container
- `password` root password of user root for login and access.
- `database_name` Create a new database/schema with given name.

### HDFS on Docker

**Note that this part is not suggested on OSX (mac), becasue the containers' newtork is limited on OSX.**

Pull a well-known third-party hadoop image from docker store. You can use `hadoop-docker:tag` to specify the Hadoop
version (`tag`) you want.

#### Set a HDFS Container

```bash
docker pull sequenceiq/hadoop-docker
```

Launch a Hadoop container with a exposed namenode.rpcserver.

```bash
docker run -it --add-host=moby:127.0.0.1 --ulimit memlock=2024000000:2024000000 -p 9000:9000 --name=hadoop sequenceiq/hadoop-docker /etc/bootstrap.sh -bash
```

Note that we try to launch a interactive docker container. Use the following command to check HDFS status. We also set
`memlock=2024000000` for cache size.

```
cd $HADOOP_PREFIX
bin/hdfs dfs -ls /
```

#### Configure HDFS with multiple storage types and cache

Edit `$HADOOP_PREFIX/etc/hadoop/hdfs-site.xml` and add the property below. This will turn off premission check to avoid
`Access denied for user ***. Superuser privilege is required`.

```
<property>
    <name>dfs.permissions.enabled</name>
    <value>false</value>
</property>
```

Create `/tmp/hadoop-root/dfs/data1~3` for different storage types. Delete all content in `/tmp/hadoop-root/dfs/data` and
`/tmp/hadoop-root/dfs/name`, then use `bin/hdfs namenode -format` to format HDFS.

Add the following properties to `$HADOOP_PREFIX/etc/hadoop/hdfs-site.xml`.

```
<property>
	<name>dfs.datanode.max.locked.memory</name>
	<value>2024000000</value>
</property>
<property>
	<name>dfs.datanode.data.dir</name>
	<value>[DISK]/tmp/hadoop-root/dfs/data,[SSD]/tmp/hadoop-root/dfs/data1,[RAM_DISK]/tmp/hadoop-root/dfs/data2,[ARCHIVE]/tmp/hadoop-root/dfs/data3</value>
</property>
<property>
	<name>dfs.blocksize</name>
	<value>1048576</value>
	</property>
<property>
	<name>dfs.permissions.enabled</name>
	<value>false</value>
</property>
```

Restart HDFS.

```
$HADOOP_PREFIX/sbin/stop-dfs.sh
$HADOOP_PREFIX/sbin/start-dfs.sh
```

Use `bin/hdfs dfsadmin -report` to check status.

## SSM Configuration

### MetaStore

#### Configure MetaStore for SSM

Assuming you are in SSM root directory, modify `conf/druid.xml` to enable SSM to connect with postgres.

```
	<entry key="url">jdbc:postgresql://localhost/{database_name}</entry>
	<entry key="username">root</entry>
	<entry key="password">{root_password}</entry>
```

Wait for at least 10 seconds. Then, use `bin/start-smart.sh -format` to format (re-init) the database. Also, you can use
this command to clear all data in database in tests.

#### Stop/Remove Postgres container

You can use the `docker stop {contrainer_name}` to stop postgres container. Then, this postgres service cannot be
accessed, until you start it again with `docker start {contrainer_name}`. Note that, `stop/start` will not remove any
data from your postgres container.

Use `docker rm {container_name}` to remove postgres container, if this container is not necessary. If you don't remember
the specific name of container, you can use `docker ps -a` to look for it.

### HDFS

### Configure HDFS for SSM

Configure `namenode.rpcserver` in `smart-site.xml`.

```xml

<configuration>
    <property>
        <name>smart.dfs.namenode.rpcserver</name>
        <value>hdfs://localhost:9000</value>
        <description>Namenode rpcserver</description>
    </property>
</configuration>
```

## More Information

1. [Docker](https://www.docker.com/)
2. [Docker doc](https://docs.docker.com/)
3. [Postgres on Docker](https://store.docker.com/images/postgres)
4. [Docker CN mirror](https://www.docker-cn.com/registry-mirror) 
