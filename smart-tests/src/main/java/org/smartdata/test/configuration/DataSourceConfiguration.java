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
package org.smartdata.test.configuration;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.jdbc.DataSourceBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.jdbc.core.JdbcTemplate;

import javax.sql.DataSource;

@Configuration
public class DataSourceConfiguration {

  @Bean
  @Primary
  @ConfigurationProperties("ssm-metastore-db.datasource")
  public DataSource ssmMetastoreDataSource() {
    return DataSourceBuilder.create().build();
  }

  @Bean
  public JdbcTemplate ssmMetastoreJdbcTemplate(DataSource ssmMetastoreDataSource) {
    return new JdbcTemplate(ssmMetastoreDataSource);
  }

  @Bean
  @ConfigurationProperties("ssm-hive-db.datasource")
  public DataSource ssmHiveDataSource() {
    return DataSourceBuilder.create().build();
  }

  @Bean
  @ConditionalOnProperty(name = "hms-profile-enabled", havingValue = "true")
  @ConfigurationProperties("ssm-hive2-db.datasource")
  public DataSource ssmHive2DataSource() {
    return DataSourceBuilder.create().build();
  }

  @Bean
  @ConfigurationProperties("hive-server2-db.datasource")
  public DataSource hiveServer2DataSource() {
    return DataSourceBuilder.create().build();
  }

  @Bean
  @ConditionalOnProperty(name = "hms-profile-enabled", havingValue = "true")
  @ConfigurationProperties("target-hive-server2-db.datasource")
  public DataSource targetHiveServer2DataSource() {
    return DataSourceBuilder.create().build();
  }
}
