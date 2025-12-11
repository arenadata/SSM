# Apache Ozone cluster for manual testing

### Start cluster

```shell
ADMIN_USER=*ssm user* docker compose up -d
```

### Creating volumes

```shell
docker compose exec -it om "/bin/bash"
ozone sh volume create /vol1
ozone sh volume create /vol2 -u=another_owner
```

### Creating buckets

```shell
docker compose exec -it om "/bin/bash"
ozone sh bucket create /vol1/bucket1
ozone sh bucket create /vol2/bucket1 -u=another_owner
```

### Creating keys

```shell
docker compose exec -it om "/bin/bash"
echo "test" > ./test.txt
ozone sh key put --replication=ONE --type=RATIS /vol1/bucket1/test.txt test.txt
```
