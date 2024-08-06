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
import org.smartdata.model.FileDiff;
import org.smartdata.model.FileDiffState;
import org.smartdata.model.FileDiffType;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

import static org.junit.Assert.assertEquals;


public class TestFileDiffDao extends TestDaoBase {
  private FileDiffDao fileDiffDao;

  @Before
  public void initFileDiffDAO() {
    fileDiffDao = daoProvider.fileDiffDao();
  }

  @Test
  public void testInsertAndGetSingleRecord() {
    FileDiff fileDiff = new FileDiff();
    fileDiff.setParameters(new HashMap<String, String>());
    fileDiff.getParameters().put("-test", "test");
    fileDiff.setSrc("test");
    fileDiff.setState(FileDiffState.PENDING);
    fileDiff.setDiffType(FileDiffType.APPEND);
    fileDiff.setCreateTime(1);
    fileDiffDao.insert(fileDiff);
    Assert.assertTrue(fileDiffDao.getAll().get(0).equals(fileDiff));
  }

  @Test
  public void testBatchUpdateAndQuery() {
    List<FileDiff> fileDiffs = new ArrayList<>();
    FileDiff fileDiff = new FileDiff();
    fileDiff.setDiffId(1);
    fileDiff.setParameters(new HashMap<>());
    fileDiff.setSrc("test");
    fileDiff.setState(FileDiffState.RUNNING);
    fileDiff.setDiffType(FileDiffType.APPEND);
    fileDiff.setCreateTime(1);
    fileDiffs.add(fileDiff);

    fileDiff = new FileDiff();
    fileDiff.setDiffId(2);
    fileDiff.setParameters(new HashMap<>());
    fileDiff.setSrc("src");
    fileDiff.setState(FileDiffState.PENDING);
    fileDiff.setDiffType(FileDiffType.APPEND);
    fileDiff.setCreateTime(1);
    fileDiffs.add(fileDiff);

    fileDiffDao.insert(fileDiffs);
    List<FileDiff> fileInfoList = fileDiffDao.getAll();
    assertEquals(fileDiffs, fileInfoList);

    //update
    List<Long> dids = new ArrayList<>();
    dids.add(1L);
    dids.add(2L);
    List<String> parameters = new ArrayList<>();
    parameters.add(fileDiffs.get(0).getParametersJsonString());
    parameters.add(fileDiffs.get(1).getParametersJsonString());
    List<FileDiffState> fileDiffStates = new ArrayList<>();
    fileDiffStates.add(FileDiffState.APPLIED);
    fileDiffStates.add(fileDiffs.get(1).getState());

    fileDiffDao.batchUpdate(dids, fileDiffStates, parameters);

    fileInfoList = fileDiffDao.getAll();

    assertEquals(FileDiffState.APPLIED, fileInfoList.get(0).getState());
    fileDiffDao.batchUpdate(dids, FileDiffState.MERGED);
    assertEquals(FileDiffState.MERGED, fileDiffDao.getAll().get(0).getState());

  }

  @Test
  public void testBatchInsertAndQuery() {
    List<FileDiff> fileDiffs = new ArrayList<>();
    FileDiff fileDiff = new FileDiff();
    fileDiff.setParameters(new HashMap<String, String>());
    fileDiff.setSrc("test");
    fileDiff.setState(FileDiffState.RUNNING);
    fileDiff.setDiffType(FileDiffType.APPEND);
    fileDiff.setCreateTime(1);
    fileDiffs.add(fileDiff);

    fileDiff = new FileDiff();
    fileDiff.setParameters(new HashMap<String, String>());
    fileDiff.setSrc("src");
    fileDiff.setState(FileDiffState.PENDING);
    fileDiff.setDiffType(FileDiffType.APPEND);
    fileDiff.setCreateTime(1);
    fileDiffs.add(fileDiff);

    fileDiffDao.insert(fileDiffs);
    List<FileDiff> fileInfoList = fileDiffDao.getAll();
    for (int i = 0; i < 2; i++) {
      Assert.assertTrue(fileInfoList.get(i).equals(fileDiffs.get(i)));
    }
    List<String> paths = fileDiffDao.getSyncPath(0);
    Assert.assertTrue(paths.size() == 1);
    Assert.assertTrue(fileDiffDao.getPendingDiff("src").size() == 1);
    Assert.assertTrue(fileDiffDao.getByState("test", FileDiffState.RUNNING).size() == 1);
  }

  @Test
  public void testUpdate() {
    FileDiff fileDiff1 = new FileDiff();
    fileDiff1.setDiffId(1);
    fileDiff1.setRuleId(1);
    fileDiff1.setParameters(new HashMap<>());
    fileDiff1.setSrc("test");
    fileDiff1.setState(FileDiffState.PENDING);
    fileDiff1.setDiffType(FileDiffType.APPEND);
    fileDiff1.setCreateTime(1);

    FileDiff fileDiff2 = new FileDiff();
    fileDiff2.setDiffId(2);
    fileDiff2.setRuleId(1);
    fileDiff2.setParameters(new HashMap<>());
    fileDiff2.setSrc("src");
    fileDiff2.setState(FileDiffState.PENDING);
    fileDiff2.setDiffType(FileDiffType.APPEND);
    fileDiff2.setCreateTime(1);

    fileDiffDao.insert(Arrays.asList(fileDiff1, fileDiff2));
    fileDiffDao.update(1, FileDiffState.RUNNING);
    fileDiff1.setState(FileDiffState.RUNNING);

    assertEquals(fileDiff1, fileDiffDao.getById(1));
    assertEquals(1, fileDiffDao.getPendingDiff().size());
    fileDiff1.getParameters().put("-offset", "0");
    fileDiff1.setSrc("test1");
    fileDiff2.setCreateTime(2);
    fileDiff2.setRuleId(2);
    fileDiff2.setDiffType(FileDiffType.RENAME);
    fileDiffDao.update(Arrays.asList(fileDiff1, fileDiff2));
    Assert.assertEquals(fileDiff1, fileDiffDao.getById(1));
    Assert.assertEquals(fileDiff2, fileDiffDao.getById(2));
  }

  @Test
  public void testDeleteUselessRecords() {
    FileDiff[] fileDiffs = new FileDiff[2];
    fileDiffs[0] = new FileDiff();
    fileDiffs[0].setDiffId(1);
    fileDiffs[0].setRuleId(1);
    fileDiffs[0].setParameters(new HashMap<String, String>());
    fileDiffs[0].setSrc("test");
    fileDiffs[0].setState(FileDiffState.PENDING);
    fileDiffs[0].setDiffType(FileDiffType.APPEND);
    fileDiffs[0].setCreateTime(1);

    fileDiffs[1] = new FileDiff();
    fileDiffs[1].setDiffId(2);
    fileDiffs[0].setRuleId(1);
    fileDiffs[1].setParameters(new HashMap<String, String>());
    fileDiffs[1].setSrc("src");
    fileDiffs[1].setState(FileDiffState.PENDING);
    fileDiffs[1].setDiffType(FileDiffType.APPEND);
    fileDiffs[1].setCreateTime(2);

    fileDiffDao.insert(fileDiffs);
    assertEquals(fileDiffDao.getUselessRecordsNum(), 0);
    fileDiffDao.update(1, FileDiffState.APPLIED);
    assertEquals(fileDiffDao.getUselessRecordsNum(), 1);
    fileDiffDao.update(2, FileDiffState.FAILED);
    assertEquals(fileDiffDao.getUselessRecordsNum(), 2);
    fileDiffDao.update(2, FileDiffState.DELETED);
    assertEquals(fileDiffDao.getUselessRecordsNum(), 2);
    fileDiffDao.deleteUselessRecords(1);
    assertEquals(fileDiffDao.getAll().size(), 1);
  }
}
