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
import org.junit.After;
import org.junit.Before;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.AfterParam;
import org.junit.runners.Parameterized.BeforeParam;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;
import org.smartdata.conf.SmartConf;
import org.smartdata.metastore.dao.DaoProvider;
import org.smartdata.metastore.dao.DaoProviderFactory;
import org.smartdata.metastore.db.DBHandlersFactory;
import org.smartdata.metastore.db.DbSchemaManager;
import org.smartdata.metastore.db.metadata.DbMetadataProvider;
import org.springframework.jdbc.support.JdbcTransactionManager;
import org.springframework.transaction.PlatformTransactionManager;
import org.testcontainers.jdbc.ContainerDatabaseDriver;

import java.io.InputStream;
import java.util.Properties;

import static com.alibaba.druid.pool.DruidDataSourceFactory.PROP_DRIVERCLASSNAME;
import static com.alibaba.druid.pool.DruidDataSourceFactory.PROP_URL;

@RunWith(Parameterized.class)
public abstract class TestDaoBase {
  @Parameter(0)
  public DBType dbType;

  @Parameter(1)
  public String driverClassName;

  @Parameter(2)
  public String dbUrl;

  protected static DaoProvider daoProvider;
  protected static DruidPool druidPool;
  protected static DbSchemaManager dbSchemaManager;
  protected static DbMetadataProvider dbMetadataProvider;
  protected static MetaStore metaStore;

  @Parameters(name = "{0}")
  public static Object[] parameters() {
    return new Object[][]{
        {DBType.POSTGRES, ContainerDatabaseDriver.class.getName(),
            "jdbc:tc:postgresql:12.19:///ssm_postgres"},
    };
  }

  @BeforeParam
  public static void initDao(DBType dbType, String driverClassName, String dbUrl) throws Exception {
    InputStream in = TestDaoBase.class.getClassLoader()
        .getResourceAsStream("druid-template.xml");
    Properties druidProps = new Properties();
    druidProps.loadFromXML(in);
    druidProps.setProperty(PROP_DRIVERCLASSNAME, driverClassName);
    druidProps.setProperty(PROP_URL, dbUrl);

    DBHandlersFactory dbHandlersFactory = new DBHandlersFactory();

    druidPool = new DruidPool(new SmartConf(), druidProps);
    dbSchemaManager = dbHandlersFactory
        .createDbManager(druidPool, new Configuration());
    PlatformTransactionManager transactionManager =
        new JdbcTransactionManager(druidPool.getDataSource());
    daoProvider = new DaoProviderFactory()
        .createDaoProvider(druidPool, transactionManager, dbType);
    dbMetadataProvider = dbHandlersFactory.createDbMetadataProvider(druidPool, dbType);
    metaStore = new MetaStore(
        druidPool, dbSchemaManager, daoProvider, dbMetadataProvider, transactionManager);
  }

  @Before
  public void initDb() throws Exception {
    dbSchemaManager.initializeDatabase();
  }

  @After
  public void clearDb() throws Exception {
    dbSchemaManager.clearDatabase();
  }

  @AfterParam
  public static void closeDao() {
    if (druidPool != null) {
      druidPool.close();
    }
  }
}
