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
package org.smartdata.metastore.dao;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.smartdata.metastore.TestDaoBase;
import org.smartdata.model.BackUpInfo;
import org.springframework.dao.EmptyResultDataAccessException;

import java.util.List;

public class TestBackUpInfoDao extends TestDaoBase {
  private BackUpInfoDao backUpInfoDao;

  @Before
  public void initBackUpInfoDao() {
    backUpInfoDao = daoProvider.backUpInfoDao();
  }

  @Test
  public void testInsertAndGetSingleRecord() {
    BackUpInfo backUpInfo = BackUpInfo.builder()
        .rid(1)
        .period(1)
        .dest("")
        .src("")
        .srcPattern("")
        .build();

    backUpInfoDao.insert(backUpInfo);
    Assert.assertEquals(backUpInfo, backUpInfoDao.getByRid(1));
  }

  @Test
  public void testDelete() {
    backUpInfoDao.delete(1L);
    BackUpInfo[] backUpInfos = new BackUpInfo[2];
    backUpInfos[0] = new BackUpInfo(1, "test", "test", 1);
    backUpInfos[1] = new BackUpInfo(2, "test", "test", 1);

    backUpInfoDao.insert(backUpInfos);
    backUpInfoDao.delete(1L);
    Assert.assertTrue(backUpInfoDao.getByRid(2).equals(backUpInfos[1]));
    try {
      backUpInfoDao.getByRid(1);
    } catch (EmptyResultDataAccessException e) {
    }
  }

  @Test
  public void testBatchInsert() {
    BackUpInfo[] backUpInfos = new BackUpInfo[2];
    backUpInfos[0] = new BackUpInfo(1, "test", "test", 1);
    backUpInfos[1] = new BackUpInfo(2, "test", "test", 1);

    backUpInfoDao.insert(backUpInfos);


    Assert.assertTrue(backUpInfoDao.getByRid(1).equals(backUpInfos[0]));
    Assert.assertTrue(backUpInfoDao.getByRid(2).equals(backUpInfos[1]));
  }

  @Test
  public void testUpdate() {
    BackUpInfo backUpInfo = BackUpInfo.builder()
        .rid(1)
        .src("test")
        .dest("test")
        .period(1)
        .srcPattern("")
        .build();

    backUpInfoDao.insert(backUpInfo);
    backUpInfoDao.update(1, 2);

    backUpInfo = backUpInfo.toBuilder()
        .period(2)
        .build();

    Assert.assertEquals(backUpInfo, backUpInfoDao.getByRid(1));
  }

  @Test
  public void testgetBySrc() {
    Assert.assertTrue(backUpInfoDao.getByDest("1").size() == 0);
    BackUpInfo[] backUpInfos = new BackUpInfo[2];
    backUpInfos[0] = new BackUpInfo(1, "test", "test", 1);
    backUpInfos[1] = new BackUpInfo(2, "test", "test", 1);

    backUpInfoDao.insert(backUpInfos);
    List<BackUpInfo> list = backUpInfoDao.getBySrc("test");
    Assert.assertTrue(list.size() == 2);
    Assert.assertTrue(list.get(0).equals(backUpInfos[0]));
    Assert.assertTrue(list.get(1).equals(backUpInfos[1]));
    Assert.assertTrue(backUpInfoDao.getCountByRid(1) == 0);
  }
}
