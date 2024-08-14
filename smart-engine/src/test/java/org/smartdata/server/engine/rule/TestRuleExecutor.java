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
package org.smartdata.server.engine.rule;

import org.junit.Before;
import org.junit.Test;
import org.smartdata.metastore.TestDaoBase;
import org.smartdata.metastore.dao.MetaStoreHelper;

import static org.junit.Assert.assertTrue;

public class TestRuleExecutor extends TestDaoBase {
  private MetaStoreHelper metaStoreHelper;

  @Before
  public void initActionDao() {
    metaStoreHelper = new MetaStoreHelper(druidPool.getDataSource());
  }

  @Test
  public void generateSQL() {
    String countFilter = "";
    String newTable = "test";
    String sql;
    long interval = 60000;
    long currentTimeMillis = System.currentTimeMillis();
    sql = RuleExecutor.generateSQL(newTable, countFilter, metaStore, currentTimeMillis - interval,
        currentTimeMillis);
    try {
      metaStoreHelper.execute(sql);
      assertTrue(sql.contains("GROUP BY fid ;"));
      metaStoreHelper.dropTable(newTable);
    } catch (Exception e) {
      assertTrue(false);
    }
    // Test with count filter
    countFilter = "> 10";
    sql = RuleExecutor.generateSQL(newTable, countFilter, metaStore, currentTimeMillis - interval,
        currentTimeMillis);
    try {
      metaStoreHelper.execute(sql);
      assertTrue(sql.contains("GROUP BY fid HAVING count(*) > 10 ;"));
      metaStoreHelper.dropTable(newTable);
    } catch (Exception e) {
      assertTrue(false);
    }
  }
}
