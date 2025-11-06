# Demo

### Connect to beeline
```shell
/opt/hive/bin/beeline -u 'jdbc:hive2://localhost:10000/'
```

### Create entities
```hiveql
create database db1;
create table db1.t1(i int);
create table db1.t2(r int);
insert into db1.t1 values (1), (2), (3);
ANALYZE TABLE db1.t1 COMPUTE STATISTICS FOR COLUMNS;

create database db2;
create table db2.t1(g int);

create table db2.t3(g int);
drop table db2.t1;
```

### Inspect entities
```hiveql
show databases;
show tables in db2;

DESCRIBE extended db2.t1;
DESCRIBE extended db1.t2;
```

### Create SSM rule
```
hms : name matches "db1.*" | hms-sync -dest thrift://target-hive-metastore:9083/ -cascade -nameservice_rename "source target"
hms : name matches "db2.*" | hms-sync -dest thrift://target-hive-metastore:9083/ -cascade -nameservice_rename "source target"
```