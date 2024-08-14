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

import org.apache.hadoop.conf.Configuration;
import org.junit.Assert;
import org.junit.Test;
import org.smartdata.metastore.dao.DaoProvider;
import org.smartdata.metastore.dao.postgres.PostgresDaoProvider;
import org.smartdata.metastore.db.DBHandlersFactory;
import org.smartdata.metastore.db.DbSchemaManager;
import org.smartdata.metastore.db.metadata.DbMetadataProvider;
import org.smartdata.model.RuleInfo;
import org.smartdata.model.RuleState;
import org.springframework.jdbc.support.JdbcTransactionManager;
import org.springframework.transaction.PlatformTransactionManager;
import org.testcontainers.jdbc.ContainerDatabaseDriver;

import java.io.InputStream;
import java.util.Properties;

import static com.alibaba.druid.pool.DruidDataSourceFactory.PROP_DRIVERCLASSNAME;
import static com.alibaba.druid.pool.DruidDataSourceFactory.PROP_URL;

public class TestDruid {

  @Test
  public void test() throws Exception {
    InputStream in = getClass().getClassLoader()
        .getResourceAsStream("druid-template.xml");
    Properties p = new Properties();
    p.loadFromXML(in);
    p.setProperty(PROP_URL, "jdbc:tc:postgresql:12.19:///ssm_postgres");
    p.setProperty(PROP_DRIVERCLASSNAME, ContainerDatabaseDriver.class.getName());
    DruidPool druidPool = new DruidPool(p);
    DBHandlersFactory dbHandlersFactory = new DBHandlersFactory();
    DbSchemaManager dbSchemaManager = dbHandlersFactory
        .createDbManager(druidPool, new Configuration());
    PlatformTransactionManager transactionManager =
        new JdbcTransactionManager(druidPool.getDataSource());
    DaoProvider daoProvider = new PostgresDaoProvider(druidPool, transactionManager);
    DbMetadataProvider dbMetadataProvider =
        dbHandlersFactory.createDbMetadataProvider(druidPool, DBType.POSTGRES);
    MetaStore adapter = new MetaStore(
        druidPool, dbSchemaManager, daoProvider, dbMetadataProvider, transactionManager);
    dbSchemaManager.initializeDatabase();
    String rule = "file : accessCount(10m) > 20 \n\n"
        + "and length() > 3 | cache";
    long submitTime = System.currentTimeMillis();
    RuleInfo info1 = new RuleInfo(0, submitTime,
        rule, RuleState.ACTIVE, 0, 0, 0);
    Assert.assertTrue(adapter.insertNewRule(info1));
    RuleInfo info11 = adapter.getRuleInfo(info1.getId());
    Assert.assertEquals(info1, info11);

    long now = System.currentTimeMillis();
    adapter.updateRuleInfo(info1.getId(), RuleState.DELETED, now, 1, 1);
    RuleInfo info12 = adapter.getRuleInfo(info1.getId());
    Assert.assertEquals(info12.getLastCheckTime(), now);

    druidPool.close();
  }
}
