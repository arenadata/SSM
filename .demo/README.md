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
create table db1.t2d(r int);
create table db1.t2d12e(r int);
create table db1.t2de1(r int);
create table db1.t2de(r int);
create table db1.t2d123(r int);
create table db1.t221d(r int);
create table db1.t22313d(r int);
create table db1.t233d(r int);
create table db1.t22d(r int);
create table db1.t2213d(r int);
create table db1.t21123d(r int);
create table db1.t22e313d(r int);
create table db1.t2323d(r int);
create table db1.t2e2d(r int);
create table db1.t22c13d(r int);
create table db1.t2e1123d(r int);
create table db1.tt2 (r int);
create table db1.tt3 (r int);
create table db1.tt4 (r int);
create table db1.tt5 (r int);
create table db1.tt6 (r int);
create table db1.tt7 (r int);
create table db1.tt8 (r int);
create table db1.tt9 (r int);
create table db1.tt10 (r int);
create table db1.tt11 (r int);
create table db1.tt12 (r int);
create table db1.tt13 (r int);
create table db1.tt14 (r int);
create table db1.tt15 (r int);
create table db1.tt16 (r int);
create table db1.tt17 (r int);
create table db1.tt18 (r int);
create table db1.tt19 (r int);
create table db1.tt20 (r int);
create table db1.tt21 (r int);
create table db1.tt22 (r int);
create table db1.tt23 (r int);
create table db1.tt24 (r int);
create table db1.tt25 (r int);
create table db1.tt26 (r int);
create table db1.tt27 (r int);
create table db1.tt28 (r int);
create table db1.tt29 (r int);
create table db1.tt30 (r int);
create table db1.tt31 (r int);
create table db1.tt32 (r int);
create table db1.tt33 (r int);
create table db1.tt34 (r int);
create table db1.tt35 (r int);
create table db1.tt36 (r int);
create table db1.tt37 (r int);
create table db1.tt38 (r int);
create table db1.tt39 (r int);
create table db1.tt40 (r int);
create table db1.tt41 (r int);
create table db1.tt42 (r int);
create table db1.tt43 (r int);
create table db1.tt44 (r int);
create table db1.tt45 (r int);
create table db1.tt46 (r int);
create table db1.tt47 (r int);
create table db1.tt48 (r int);
create table db1.tt49 (r int);
create table db1.tt50 (r int);
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
hms : name matches "db1.*" | hms-sync -dest thrift://localhost:9094/ -cascade -nameservice_rename "source target"
hms : name matches "db2.*" | hms-sync -dest thrift://target-hive-metastore:9083/ -cascade -nameservice_rename "source target"
```