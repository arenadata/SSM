# Performance Test for Data Sync[Not ready]

## Requirements
- Deploy SSM, please refer to /SSM/doc/ssm-deployment-guide.md or [ADH install guide](https://docs.arenadata.io/ru/ADH/current/get-started/start-here.html).
- Deploy two HDFS (or [ADH](https://docs.arenadata.io/ru/ADH/current/get-started/start-here.html)) clusters and configure its bin in $PATH of OS.
- Install Postgresql for SSM storing Metadata.
- Python 3.10 or higher 
### Python Environment
Python 3 (3.10 or higher) with installed requirements libs from [requirements.txt](..%2Frequirements.txt).
```
python3 --version
python3 -m venv venv
source venv/bin/activate
pip install -r ../requirements.txt
```
For use `pyarrow` ([pyarrow_create_file.py](pyarrow_create_file.py)) set environments 
and make sure that `libhdfs.so` is present in `ARROW_LIBHDFS_DIR`. Can be obtained from [hadoop dir](..%2Fhadoop). 
```
export HADOOP_HOME=/usr
export JAVA_HOME=/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.402.b06-1.el7_9.x86_64/jre
export ARROW_LIBHDFS_DIR=/usr/lib/hadoop/lib/native/
```
### HDFS and SSM Environment
Make sure SSM and HDFS are correctly installed. Before executing test scripts, please set SSM's web UI address.
```
export SSM_BASE_URL=http://{SSM_Server}:7045
```

`{SSM_Server}` is the IP address or hostname of active Smart Server.

## Configuration
Set up a file named config. For batch sync(`run_distcp`, `run_ssm_initial_sync`) test cases, the data must be generated in advance by the `make generate_data` command.
In the case of the `run_ssm_async_sync` scenario, replication occurs in parallel with data generation.

## Test cases
  1. `make run_ssm_async_sync`. Asynchronous replication of parallel generating data.
  2. `make run_ssm_initial_sync`. Batch replication of pre-prepared data using SSM sync.
  3. `make run_distcp`. Batch replication of pre-prepared data using hdfs distcp.

## Other
  1. To delete data on the source cluster, use `make delete_data`. To delete data on the source cluster, use hdfs command line.
  2. On the target cluster, writing must be allowed for the user under whom SSM is running.
  3. Create a directory for logs in advance.
  4. Clear cache between launches `sync;echo 3 > /proc/sys/vm/drop_caches`
  5. For initial performance analysis, use RuleID from the logs and the following queries in the SSM database.
     ```sql
     ---- Get execution and generation+execution time aggregates
     select 
	 min(a.finish_time - a.create_time) AS EXC_MIN, 
	 max(a.finish_time - a.create_time) AS EXC_MAX,  
	 avg(a.finish_time - a.create_time) AS EXC_AVG ,
	 min(c.state_changed_time - c.generate_time) AS GEN_EXC_MIN, 
	 max(c.state_changed_time - c.generate_time) AS GEN_EXC_MAX,  
	 avg(c.state_changed_time - c.generate_time) AS GEN_EXC_AVG  
     from action a
     join cmdlet c  on a.cid = c.cid 
     where c.rid = :rid;
     ```
     ```sql
     ---- Sorted cmds in order of waiting between generation and launch.
     select 
    	(c.state_changed_time - c.generate_time) - (a.finish_time - a.create_time), a.cid
     from action a
     join cmdlet c  on a.cid = c.cid 
     where c.rid = :rid order by (c.state_changed_time - c.generate_time) - (a.finish_time - a.create_time) DESC;
     ```
  6. You can use a script `../hdfs_check_sum_src_dest_clusters.py -h` to check the data