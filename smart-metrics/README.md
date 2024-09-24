# Supported metrics

| Name                                                | Description                                                                                             |
|-----------------------------------------------------|---------------------------------------------------------------------------------------------------------|
| access_events_count_total                           | Access events count                                                                                     |
| application_ready_time_seconds                      | Time taken for the application to be ready to service requests                                          |
| application_started_time_seconds                    | Time taken to start the application                                                                     |
| db_pool_druid_connections_active_count              | The number of active connections in the connection pool                                                 |
| db_pool_druid_connections_commit_count_total        | The number of commits called                                                                            |
| db_pool_druid_connections_connected_total           | The number of opened connections in the connection pool                                                 |
| db_pool_druid_connections_created_total             | The number of created connections in the connection pool                                                |
| db_pool_druid_connections_error_connect_count_total | The number of connection errors during query executions                                                 |
| db_pool_druid_connections_error_count_total         | The number of errors during query executions                                                            |
| db_pool_druid_connections_pooling_count             | The number of idle connections in the connection pool                                                   |
| db_pool_druid_connections_rollback_count_total      | The number of rollbacks called                                                                          |
| db_pool_druid_lock_wait_queue_size                  | The size of threads waiting for connection from pool                                                    |
| db_pool_druid_lock_wait_time_ms                     | The total time of threads waiting for connection from pool                                              |
| db_pool_druid_statements_execute_count_total        | The number of prepared statements executions                                                            |
| db_pool_druid_statements_prepare_count_total        | The number of prepared statements prepare method calls                                                  |
| db_pool_druid_statements_running_count              | The number of running prepared statements                                                               |
| executor_active_threads                             | The approximate number of threads that are actively executing tasks                                     |
| executor_completed_tasks_total                      | The approximate total number of tasks that have completed execution                                     |
| executor_idle_seconds                               | Executor idle time                                                                                      |
| executor_idle_seconds_max                           | Maximum idle time for executor                                                                          |
| executor_pool_core_threads                          | The core number of threads for the pool                                                                 |
| executor_pool_max_threads                           | The maximum allowed number of threads in the pool                                                       |
| executor_pool_size_threads                          | The current number of threads in the pool                                                               |
| executor_queue_remaining_tasks                      | The number of additional elements that this queue can ideally accept without blocking                   |
| executor_queued_tasks                               | The approximate number of tasks that are queued for execution                                           |
| executor_scheduled_once_total                       | The total number of tasks scheduled once                                                                |
| executor_scheduled_repetitively_total               | The total number of tasks scheduled repetitively                                                        |
| executor_seconds                                    | Total time spent by executor                                                                            |
| executor_seconds_max                                | Maximum time spent by executor                                                                          |
| http_server_requests_seconds                        | Duration of HTTP server request handling                                                                |
| http_server_requests_seconds_max                    | Maximum duration of HTTP server request handling                                                        |
| jvm_buffer_count_buffers                            | An estimate of the number of buffers in the pool                                                        |
| jvm_buffer_memory_used_bytes                        | An estimate of the memory that the Java virtual machine is using for this buffer pool                   |
| jvm_buffer_total_capacity_bytes                     | An estimate of the total capacity of the buffers in this pool                                           |
| jvm_classes_loaded_classes                          | The number of classes that are currently loaded in the Java virtual machine                             |
| jvm_classes_unloaded_classes_total                  | The total number of classes unloaded since the Java virtual machine has started execution               |
| jvm_gc_live_data_size_bytes                         | Size of long-lived heap memory pool after reclamation                                                   |
| jvm_gc_max_data_size_bytes                          | Max size of long-lived heap memory pool                                                                 |
| jvm_gc_memory_allocated_bytes_total                 | Incremented for an increase in the size of the (young) heap memory pool after one GC to before the next |
| jvm_gc_memory_promoted_bytes_total                  | Count of positive increases in the size of the old generation memory pool before GC to after GC         |
| jvm_gc_overhead_percent                             | Percent of CPU time used by GC activities over the last lookback period or since monitoring began       |
| jvm_gc_pause_seconds                                | Time spent in GC pause                                                                                  |
| jvm_gc_pause_seconds_max                            | Maximum time spent in GC pause                                                                          |
| jvm_memory_committed_bytes                          | The amount of memory in bytes that is committed for the Java virtual machine to use                     |
| jvm_memory_max_bytes                                | The maximum amount of memory in bytes that can be used for memory management                            |
| jvm_memory_usage_after_gc_percent                   | The percentage of long-lived heap pool used after the last GC event, in the range [0..1]                |
| jvm_memory_used_bytes                               | The amount of used memory                                                                               |
| jvm_threads_daemon_threads                          | The current number of live daemon threads                                                               |
| jvm_threads_live_threads                            | The current number of live threads including both daemon and non-daemon threads                         |
| jvm_threads_peak_threads                            | The peak live thread count since the Java virtual machine started or peak was reset                     |
| jvm_threads_states_threads                          | The current number of threads in each state                                                             |
| process_cpu_usage                                   | The recent CPU usage for the Java Virtual Machine process                                               |
| process_files_max_files                             | The maximum file descriptor count                                                                       |
| process_files_open_files                            | The open file descriptor count                                                                          |
| process_start_time_seconds                          | Start time of the process since Unix epoch                                                              |
| process_uptime_seconds                              | The uptime of the Java virtual machine                                                                  |
| system_cpu_count                                    | The number of processors available to the Java virtual machine                                          |
| system_cpu_usage                                    | The recent CPU usage of the system the application is running in                                        |
| system_load_average_1m                              | The sum of runnable entities queued and running on available processors averaged over a period of time  |
| tomcat_sessions_active_current_sessions             | The number of current active sessions                                                                   |
| tomcat_sessions_active_max_sessions                 | The maximum number of active sessions                                                                   |
| tomcat_sessions_alive_max_seconds                   | The maximum number of seconds a session was alive                                                       |
| tomcat_sessions_created_sessions_total              | The total number of sessions created                                                                    |
| tomcat_sessions_expired_sessions_total              | The total number of expired sessions                                                                    |
| tomcat_sessions_rejected_sessions_total             | The total number of rejected sessions                                                                   |
