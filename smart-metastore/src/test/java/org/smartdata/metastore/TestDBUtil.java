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
package org.smartdata.metastore;

import org.apache.hadoop.conf.Configuration;
import org.smartdata.metastore.dao.AccessCountTable;
import org.smartdata.metastore.dao.AccessCountTableDeque;
import org.smartdata.metastore.db.DBHandlersFactory;
import org.smartdata.metastore.db.DbSchemaManager;

import javax.sql.DataSource;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static org.smartdata.metastore.utils.MetaStoreUtils.SQLITE_URL_PREFIX;

/**
 * Utilities for accessing the testing database.
 */
public class TestDBUtil {
  public static String getTestDir() {
    String testdir = System.getProperty("testdir",
        System.getProperty("user.dir") + "/target/test-dir");
    return testdir;
  }

  public static String getUniqueFilePath() {
    return getTestDir() + "/" + UUID.randomUUID() + System.currentTimeMillis();
  }

  public static String getUniqueDBFilePath() {
    return getUniqueFilePath() + ".db";
  }

  public static String getUniqueSqliteUrl() {
    String dbFile = getUniqueDBFilePath();
    new File(dbFile).deleteOnExit();
    return SQLITE_URL_PREFIX + getUniqueDBFilePath();
  }

  public static void addAccessCountTableToDeque(
      AccessCountTableDeque deque, AccessCountTable table) throws Exception {
    deque.addAndNotifyListener(table)
        .get(1, TimeUnit.SECONDS);
  }

  /**
   * Get an initialized empty Sqlite database file path.
   *
   * @return
   * @throws IOException
   * @throws MetaStoreException
   * @throws ClassNotFoundException
   */
  public static String getUniqueEmptySqliteDBFile()
      throws MetaStoreException {
    try (TestSQLiteDBPool dbPool = new TestSQLiteDBPool()) {
      DbSchemaManager dbSchemaManager = new DBHandlersFactory()
          .createDbManager(dbPool, new Configuration());
      dbSchemaManager.initializeDatabase();
      return dbPool.dbFilePath;
    } catch (Exception e) {
      throw new MetaStoreException(e);
    }
  }

  public static boolean copyFile(String srcPath, String destPath) {
    boolean flag = false;
    File src = new File(srcPath);
    if (!src.exists()) {
      System.out.println("source file:" + srcPath + "not exist");
      return false;
    }
    File dest = new File(destPath);
    if (dest.exists()) {
      dest.delete();
    } else {
      if (!dest.getParentFile().exists()) {
        if (!dest.getParentFile().mkdirs()) {
          return false;
        }
      }
    }

    BufferedInputStream in = null;
    PrintStream out = null;

    try {
      in = new BufferedInputStream(new FileInputStream(src));
      out = new PrintStream(
          new BufferedOutputStream(
              new FileOutputStream(dest)));

      byte[] buffer = new byte[1024 * 100];
      int len = -1;
      while ((len = in.read(buffer)) != -1) {
        out.write(buffer, 0, len);
      }
      dest.deleteOnExit();
      return true;
    } catch (Exception e) {
      System.out.println("copying failed" + e.getMessage());
      flag = true;
      return false;
    } finally {
      try {
        in.close();
        out.close();
        if (flag) {
          dest.delete();
        }
      } catch (IOException e) {
        e.printStackTrace();
      }
    }
  }

  private static class TestSQLiteDBPool implements DBPool, AutoCloseable {

    private final String dbFilePath;
    private Connection connection;

    public TestSQLiteDBPool() {
      this.dbFilePath = getUniqueDBFilePath();
    }

    @Override
    public Connection getConnection() {
      if (connection == null) {
        try {
          connection = createSqliteConnection(dbFilePath);
        } catch (MetaStoreException exception) {
          throw new RuntimeException(exception);
        }
      }

      return connection;
    }

    @Override
    public DataSource getDataSource() {
      return null;
    }

    @Override
    public void closeConnection(Connection conn) throws SQLException {
      conn.close();
    }

    @Override
    public void close() {
      try {
        closeConnection(connection);
        new File(dbFilePath).deleteOnExit();
      } catch (SQLException e) {
        throw new RuntimeException(e);
      }
    }

    private Connection createSqliteConnection(String dbFilePath)
        throws MetaStoreException {
      try {
        return DriverManager.getConnection(SQLITE_URL_PREFIX + dbFilePath, null, null);
      } catch (Exception e) {
        throw new MetaStoreException(e);
      }
    }
  }
}
