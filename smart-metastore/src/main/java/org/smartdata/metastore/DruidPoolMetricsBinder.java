/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.smartdata.metastore;

import com.alibaba.druid.pool.DruidDataSource;
import com.alibaba.druid.pool.DruidDataSourceMBean;
import com.alibaba.druid.stat.JdbcDataSourceStat;
import com.alibaba.druid.stat.JdbcSqlStat;
import com.alibaba.druid.stat.JdbcSqlStatMBean;
import com.alibaba.druid.stat.JdbcStatementStat;
import com.alibaba.druid.stat.JdbcStatementStatMBean;
import io.micrometer.core.instrument.FunctionCounter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tags;
import io.micrometer.core.instrument.binder.BaseUnits;
import io.micrometer.core.instrument.binder.MeterBinder;
import lombok.RequiredArgsConstructor;
import org.smartdata.conf.SmartConf;

import static org.smartdata.conf.SmartConfKeys.SMART_METRICS_DB_QUERIES_ENABLED_DEFAULT;
import static org.smartdata.conf.SmartConfKeys.SMART_METRICS_DB_QUERIES_ENABLED_KEY;

@RequiredArgsConstructor
public class DruidPoolMetricsBinder implements MeterBinder {
  private static final Tags DEFAULT_BASE_TAGS = Tags.of("component", "db");

  private final DruidDataSource druidDataSource;
  private final Tags baseTags;
  private final boolean enableSqlQueryMetrics;

  public DruidPoolMetricsBinder(DruidDataSource druidDataSource, boolean enableSqlQueryMetrics) {
    this(druidDataSource, DEFAULT_BASE_TAGS, enableSqlQueryMetrics);
  }

  @Override
  public void bindTo(MeterRegistry registry) {
    FunctionCounter.builder("db.pool.druid.connections.created",
            druidDataSource, DruidDataSourceMBean::getCreateCount)
        .tags(baseTags)
        .description("The number of created connections in the connection pool")
        .register(registry);

    FunctionCounter.builder("db.pool.druid.connections.connected",
            druidDataSource, DruidDataSourceMBean::getConnectCount)
        .tags(baseTags)
        .description("The number of opened connections in the connection pool")
        .register(registry);

    FunctionCounter.builder("db.pool.druid.connections.commit.count",
            druidDataSource, DruidDataSourceMBean::getCommitCount)
        .tags(baseTags)
        .description("The number of commits called")
        .register(registry);

    FunctionCounter.builder("db.pool.druid.connections.rollback.count",
            druidDataSource, DruidDataSourceMBean::getRollbackCount)
        .tags(baseTags)
        .description("The number of rollbacks called")
        .register(registry);

    FunctionCounter.builder("db.pool.druid.connections.error.count",
            druidDataSource, DruidDataSourceMBean::getErrorCount)
        .tags(baseTags)
        .description("The number of errors during query executions")
        .register(registry);

    FunctionCounter.builder("db.pool.druid.connections.error.connect.count",
            druidDataSource, DruidDataSourceMBean::getConnectErrorCount)
        .tags(baseTags)
        .description("The number of connection errors during query executions")
        .register(registry);

    Gauge.builder("db.pool.druid.connections.active.count",
            druidDataSource, DruidDataSourceMBean::getActiveCount)
        .tags(baseTags)
        .description("The number of active connections in the connection pool")
        .register(registry);

    Gauge.builder("db.pool.druid.connections.pooling.count",
            druidDataSource, DruidDataSourceMBean::getPoolingCount)
        .tags(baseTags)
        .description("The number of idle connections in the connection pool")
        .register(registry);

    Gauge.builder("db.pool.druid.lock.wait.queue.size",
            druidDataSource, DruidDataSourceMBean::getNotEmptyWaitThreadCount)
        .tags(baseTags)
        .description("The size of threads waiting for connection from pool")
        .register(registry);

    Gauge.builder("db.pool.druid.lock.wait.time",
            druidDataSource, DruidDataSourceMBean::getNotEmptyWaitMillis)
        .tags(baseTags)
        .description("The total time of threads waiting for connection from pool")
        .baseUnit(BaseUnits.MILLISECONDS)
        .register(registry);

    JdbcDataSourceStat dataSourceStat = druidDataSource.getDataSourceStat();

    bindTo(dataSourceStat.getStatementStat(), registry);

    if (enableSqlQueryMetrics) {
      dataSourceStat.getSqlStatMap()
          .values()
          .forEach(stat -> bindTo(stat, registry));
    }
  }

  private void bindTo(JdbcSqlStat jdbcSqlStat, MeterRegistry registry) {
    Tags tags = Tags.concat(baseTags, "query", jdbcSqlStat.getSql());

    FunctionCounter.builder("db.query.execution.success.count",
            jdbcSqlStat, JdbcSqlStatMBean::getExecuteSuccessCount)
        .tags(tags)
        .description("The number of query executions")
        .register(registry);

    FunctionCounter.builder("db.query.execution.error.count",
            jdbcSqlStat, JdbcSqlStatMBean::getErrorCount)
        .tags(tags)
        .description("The number of failing query executions")
        .register(registry);

    FunctionCounter.builder("db.query.execution.running.count",
            jdbcSqlStat, JdbcSqlStatMBean::getRunningCount)
        .tags(tags)
        .description("The number of running query executions")
        .register(registry);
  }

  private void bindTo(JdbcStatementStat statementStat, MeterRegistry registry) {
    FunctionCounter.builder("db.pool.druid.statements.prepare.count",
            statementStat, JdbcStatementStatMBean::getPrepareCallCount)
        .tags(baseTags)
        .description("The number of prepared statements prepare method calls")
        .register(registry);

    FunctionCounter.builder("db.pool.druid.statements.execute.count",
            statementStat, JdbcStatementStatMBean::getPrepareCallCount)
        .tags(baseTags)
        .description("The number of prepared statements executions")
        .register(registry);

    Gauge.builder("db.pool.druid.statements.running.count",
            statementStat, JdbcStatementStatMBean::getRunningCount)
        .tags(baseTags)
        .description("The number of running prepared statements")
        .register(registry);
  }

  public static DruidPoolMetricsBinder build(SmartConf conf, DruidDataSource druidDataSource) {
    boolean enableSqlQueryMetrics = conf.getBoolean(
        SMART_METRICS_DB_QUERIES_ENABLED_KEY,
        SMART_METRICS_DB_QUERIES_ENABLED_DEFAULT);
    return new DruidPoolMetricsBinder(druidDataSource, enableSqlQueryMetrics);
  }
}
