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
import com.alibaba.druid.pool.DruidDataSourceFactory;
import org.smartdata.conf.SmartConf;
import org.smartdata.metrics.MetricsFactory;

import javax.sql.DataSource;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.Properties;

public class DruidPool implements DBPool {
  private final DruidDataSource ds;
  private final DruidPoolMetricsBinder metricsBinder;

  public DruidPool(SmartConf conf, Properties properties) throws MetaStoreException {
    try {
      ds =
          (DruidDataSource) DruidDataSourceFactory.createDataSource(properties);
      metricsBinder = DruidPoolMetricsBinder.build(conf, ds);
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public DataSource getDataSource() {
    return ds;
  }

  public Connection getConnection() throws SQLException {
    return ds.getConnection();
  }

  public void closeConnection(Connection conn) throws SQLException {
    conn.close();
  }

  @Override
  public void bindMetrics(MetricsFactory metricFactory) {
    metricsBinder.bindTo(metricFactory.getMeterRegistry());
  }

  public void close() {
    ds.close();
  }
}
