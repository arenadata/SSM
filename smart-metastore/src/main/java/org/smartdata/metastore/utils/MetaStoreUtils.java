/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.smartdata.metastore.utils;

import com.google.common.collect.Lists;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.smartdata.conf.SmartConf;
import org.smartdata.conf.SmartConfKeys;
import org.smartdata.metastore.DBPool;
import org.smartdata.metastore.DBType;
import org.smartdata.metastore.DruidPool;
import org.smartdata.metastore.MetaStore;
import org.smartdata.metastore.MetaStoreException;
import org.smartdata.metastore.dao.DaoProvider;
import org.smartdata.metastore.dao.DaoProviderFactory;
import org.smartdata.metastore.db.DBHandlersFactory;
import org.smartdata.metastore.db.DbSchemaManager;
import org.smartdata.metastore.db.metadata.DbMetadataProvider;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.InvalidPropertiesFormatException;
import java.util.List;
import java.util.Properties;

/**
 * Utilities for table operations.
 */
public class MetaStoreUtils {
  public static final String SQLITE_URL_PREFIX = "jdbc:sqlite:";
  static final Logger LOG = LoggerFactory.getLogger(MetaStoreUtils.class);

  public static final List<String> SSM_TABLES = Lists.newArrayList(
      "access_count_table",
      "blank_access_count_info",
      "cached_file",
      "ec_policy",
      "file",
      "storage",
      "storage_hist",
      "storage_policy",
      "xattr",
      "datanode_info",
      "datanode_storage_info",
      "rule",
      "cmdlet",
      "action",
      "file_diff",
      "global_config",
      "cluster_config",
      "sys_info",
      "cluster_info",
      "backup_file",
      "file_state",
      "compression_file",
      "small_file",
      "user_info",
      "whitelist"
  );

  public static void formatDatabase(SmartConf conf) throws MetaStoreException {
    try (MetaStore metaStore = getDBAdapter(conf)) {
      metaStore.formatDataBase();
    }
  }

  public static void checkTables(SmartConf conf) throws MetaStoreException {
    try (MetaStore metaStore = getDBAdapter(conf)) {
      metaStore.checkTables();
    }
  }

  public static MetaStore getDBAdapter(
      SmartConf conf) throws MetaStoreException {
    DaoProviderFactory daoProviderFactory = new DaoProviderFactory();
    DBHandlersFactory dbHandlersFactory = new DBHandlersFactory();
    Properties properties;

    URL pathUrl = ClassLoader.getSystemResource("");
    String path = pathUrl.getPath();
    String fileName = "druid.xml";
    String expectedCpPath = path + fileName;

    LOG.info("Expected DB connection pool configuration path = {}", expectedCpPath);
    File cpConfigFile = new File(expectedCpPath);
    if (cpConfigFile.exists()) {
      LOG.info("Using pool configure file: {}", expectedCpPath);
      properties = loadDruidConfig(conf, cpConfigFile);
    } else {
      LOG.info("DB connection pool config file {} NOT found.", expectedCpPath);
      fileName = "druid-template.xml";
      expectedCpPath = path + fileName;
      cpConfigFile = new File(expectedCpPath);

      LOG.info("Using pool configure file: {}", expectedCpPath);
      properties = loadDefaultDruidConfig(conf, cpConfigFile);
    }

    DruidPool druidPool = new DruidPool(properties);
    DBType dbType = getDbType(druidPool);

    DaoProvider daoProvider = daoProviderFactory.createDaoProvider(druidPool, dbType);
    DbSchemaManager dbSchemaManager = dbHandlersFactory.createDbManager(druidPool, conf);
    DbMetadataProvider dbMetadataProvider = dbHandlersFactory
        .createDbMetadataProvider(druidPool, dbType);

    return new MetaStore(druidPool, dbSchemaManager, daoProvider, dbMetadataProvider);
  }

  /**
   * Retrieve table column names.
   *
   * @param conn
   * @param tableName
   * @return
   * @throws MetaStoreException
   */
  public static List<String> getTableColumns(Connection conn, String tableName)
      throws MetaStoreException {
    List<String> ret = new ArrayList<>();
    try {
      ResultSet res = conn.getMetaData().getColumns(null, null, tableName, null);
      while (res.next()) {
        ret.add(res.getString("COLUMN_NAME"));
      }
      return ret;
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  private static Properties loadDruidConfig(SmartConf conf, File cpConfigFile)
      throws MetaStoreException {
    Properties p = new Properties();
    try {
      p.loadFromXML(Files.newInputStream(cpConfigFile.toPath()));

      String url = conf.get(SmartConfKeys.SMART_METASTORE_DB_URL_KEY);
      if (url != null) {
        p.setProperty("url", url);
      }

      String purl = p.getProperty("url");
      if (purl == null || purl.isEmpty()) {
        purl = getDefaultSqliteDB(); // For testing
        p.setProperty("url", purl);
        LOG.warn("Database URL not specified, using " + purl);
      }

      try {
        String pw = conf
            .getPasswordFromHadoop(SmartConfKeys.SMART_METASTORE_PASSWORD);
        if (pw != null && !pw.isEmpty()) {
          p.setProperty("password", pw);
        }
      } catch (IOException e) {
        LOG.info("Can not get metastore password from hadoop provision credentials,"
            + " use the one configured in druid.xml .");
      }

      for (String key : p.stringPropertyNames()) {
        if (key.equals("password")) {
          LOG.info("\t" + key + " = **********");
        } else {
          LOG.info("\t" + key + " = " + p.getProperty(key));
        }
      }
      return p;
    } catch (InvalidPropertiesFormatException e) {
      throw new MetaStoreException(
          "Malformed druid.xml, please check the file.", e);
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  private static Properties loadDefaultDruidConfig(SmartConf conf, File cpConfigFile)
      throws MetaStoreException {
    Properties properties = new Properties();
    try {
      properties.loadFromXML(Files.newInputStream(cpConfigFile.toPath()));
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
    String url = conf.get(SmartConfKeys.SMART_METASTORE_DB_URL_KEY);
    if (url != null) {
      properties.setProperty("url", url);
    }
    for (String key : properties.stringPropertyNames()) {
      LOG.info("\t" + key + " = " + properties.getProperty(key));
    }

    return properties;
  }

  /**
   * This default behavior provided here is mainly for convenience.
   */
  private static String getDefaultSqliteDB() {
    String absFilePath = System.getProperty("user.home")
        + "/smart-test-default.db";
    return MetaStoreUtils.SQLITE_URL_PREFIX + absFilePath;
  }

  private static DBType getDbType(DBPool dbPool) throws MetaStoreException {
    try (Connection connection = dbPool.getConnection()) {
      String driver = connection.getMetaData().getDriverName();
      driver = driver.toLowerCase();
      if (driver.contains("sqlite")) {
        return DBType.SQLITE;
      } else if (driver.contains("mysql")) {
        return DBType.MYSQL;
      } else if (driver.contains("postgres")) {
        return DBType.POSTGRES;
      } else {
        throw new MetaStoreException("Unknown database: " + driver);
      }
    } catch (SQLException e) {
      throw new MetaStoreException("Error during db type determination", e);
    }
  }
}

