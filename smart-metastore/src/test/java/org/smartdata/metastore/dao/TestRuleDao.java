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
import org.smartdata.metastore.queries.sort.RuleSortField;
import org.smartdata.model.RuleInfo;
import org.smartdata.model.RuleState;
import org.smartdata.model.RulesInfo;
import org.smartdata.model.TimeInterval;
import org.smartdata.model.request.RuleSearchRequest;

import java.time.Instant;
import java.util.List;

public class TestRuleDao
    extends TestSearchableDao<RuleSearchRequest, RuleInfo, RuleSortField, Long> {

  private static final long FIRST_RULE_ID = 1;
  private static final long SECOND_RULE_ID = 2;
  private static final long THIRD_RULE_ID = 3;
  private static final long DELETED_RULE_ID = 4;

  private RuleDao ruleDao;

  @Before
  public void initRuleDao() {
    ruleDao = daoProvider.ruleDao();
  }

  @Test
  public void testInsertGetRule() {
    String rule = "file : accessCount(10m) > 20 \n\n"
        + "and length() > 3 | cache";
    long submitTime = System.currentTimeMillis();
    RuleInfo info1 = RuleInfo.builder()
        .setRuleText(rule)
        .setSubmitTime(submitTime)
        .setState(RuleState.ACTIVE)
        .build();

    ruleDao.insert(info1);
    RuleInfo info11 = ruleDao.getById(info1.getId());
    Assert.assertEquals(info1, info11);

    RuleInfo info2 = RuleInfo.builder()
        .setRuleText(rule)
        .setSubmitTime(submitTime)
        .setState(RuleState.ACTIVE)
        .build();

    ruleDao.insert(info2);
    RuleInfo info21 = ruleDao.getById(info2.getId());
    Assert.assertNotEquals(info11, info21);

    List<RuleInfo> infos = ruleDao.getAll();
    Assert.assertEquals(2, infos.size());
    ruleDao.delete(info1.getId());
    infos = ruleDao.getAll();
    Assert.assertEquals(1, infos.size());
  }

  @Test
  public void testUpdateRule() {
    String rule = "file : accessCount(10m) > 20 \n\n"
        + "and length() > 3 | cache";
    long submitTime = System.currentTimeMillis();
    RuleInfo info1 =
        RuleInfo.builder()
            .setId(20L)
            .setRuleText(rule)
            .setSubmitTime(submitTime)
            .setState(RuleState.ACTIVE)
            .setNumChecked(12)
            .setNumCmdsGen(12)
            .setLastCheckTime(12L)
            .build();

    ruleDao.insert(info1);
    long rid = ruleDao.update(info1.getId(),
        RuleState.DISABLED.getValue());
    Assert.assertEquals(info1.getId(), rid);
    info1 = ruleDao.getById(info1.getId());
    Assert.assertEquals(12L, info1.getNumChecked());

    ruleDao.update(rid, System.currentTimeMillis(), 100, 200);
    RuleInfo info2 = ruleDao.getById(rid);
    Assert.assertEquals(100L, info2.getNumChecked());
  }

  @Test
  public void testGetRulesInfo() {
    RulesInfo expectedRulesInfo = new RulesInfo(0, 0);
    Assert.assertEquals(expectedRulesInfo, ruleDao.getRulesInfo());

    insertTestRules();

    expectedRulesInfo = new RulesInfo(4, 1);
    Assert.assertEquals(expectedRulesInfo, ruleDao.getRulesInfo());

    ruleDao.delete(FIRST_RULE_ID);

    expectedRulesInfo = new RulesInfo(3, 1);
    Assert.assertEquals(expectedRulesInfo, ruleDao.getRulesInfo());

    ruleDao.delete(SECOND_RULE_ID);

    expectedRulesInfo = new RulesInfo(2, 0);
    Assert.assertEquals(expectedRulesInfo, ruleDao.getRulesInfo());
  }

  @Test
  public void testSearchWithoutFilters() {
    insertTestRules();

    testSearch(RuleSearchRequest.noFilters(),
        FIRST_RULE_ID, SECOND_RULE_ID, THIRD_RULE_ID);
  }

  @Test
  public void testSearchByIds() {
    insertTestRules();

    RuleSearchRequest searchRequest = RuleSearchRequest.builder()
        .id(FIRST_RULE_ID)
        .id(SECOND_RULE_ID)
        .id(THIRD_RULE_ID)
        .build();
    testSearch(searchRequest,
        FIRST_RULE_ID, SECOND_RULE_ID, THIRD_RULE_ID);

    searchRequest = RuleSearchRequest.builder()
        .id(FIRST_RULE_ID)
        .id(DELETED_RULE_ID)
        .includeDeletedRules(true)
        .build();
    testSearch(searchRequest, FIRST_RULE_ID, DELETED_RULE_ID);

    searchRequest = RuleSearchRequest.builder()
        .id(DELETED_RULE_ID)
        .build();
    testSearch(searchRequest);

    searchRequest = RuleSearchRequest.builder()
        .id(777L)
        .build();
    testSearch(searchRequest);
  }

  @Test
  public void testSearchByRuleText() {
    insertTestRules();

    RuleSearchRequest searchRequest = RuleSearchRequest.builder()
        .textRepresentationLike("read")
        .build();
    testSearch(searchRequest, FIRST_RULE_ID, THIRD_RULE_ID);

    searchRequest = RuleSearchRequest.builder()
        .textRepresentationLike("file: path matches")
        .build();
    testSearch(searchRequest, FIRST_RULE_ID, SECOND_RULE_ID);

    searchRequest = RuleSearchRequest.builder()
        .textRepresentationLike("fILe: PatH matches")
        .build();
    testSearch(searchRequest, FIRST_RULE_ID, SECOND_RULE_ID);

    searchRequest = RuleSearchRequest.builder()
        .textRepresentationLike("wrong rule")
        .build();
    testSearch(searchRequest);
  }

  @Test
  public void testSearchBySubmissionTime() {
    insertTestRules();

    RuleSearchRequest searchRequest = RuleSearchRequest.builder()
        .submissionTime(new TimeInterval(
            Instant.ofEpochMilli(0), Instant.now()))
        .build();
    testSearch(searchRequest,
        FIRST_RULE_ID, SECOND_RULE_ID, THIRD_RULE_ID);

    searchRequest = RuleSearchRequest.builder()
        .submissionTime(new TimeInterval(
            Instant.ofEpochMilli(2), Instant.ofEpochMilli(11)))
        .includeDeletedRules(true)
        .build();
    testSearch(searchRequest, SECOND_RULE_ID);

    searchRequest = RuleSearchRequest.builder()
        .submissionTime(new TimeInterval(
            Instant.ofEpochMilli(14), Instant.now()))
        .build();
    testSearch(searchRequest);
  }

  @Test
  public void testSearchByState() {
    insertTestRules();

    RuleSearchRequest searchRequest = RuleSearchRequest.builder()
        .state(RuleState.NEW)
        .state(RuleState.ACTIVE)
        .state(RuleState.DISABLED)
        .state(RuleState.FINISHED)
        .build();
    testSearch(searchRequest,
        FIRST_RULE_ID, SECOND_RULE_ID, THIRD_RULE_ID);

    searchRequest = RuleSearchRequest.builder()
        .state(RuleState.DISABLED)
        .state(RuleState.DELETED)
        .build();
    testSearch(searchRequest, THIRD_RULE_ID, DELETED_RULE_ID);

    searchRequest = RuleSearchRequest.builder()
        .state(RuleState.DISABLED)
        .includeDeletedRules(true)
        .build();
    testSearch(searchRequest, THIRD_RULE_ID);

    searchRequest = RuleSearchRequest.builder()
        .state(RuleState.FINISHED)
        .build();
    testSearch(searchRequest);

    searchRequest = RuleSearchRequest.builder()
        .state(RuleState.DELETED)
        .build();
    testSearch(searchRequest, DELETED_RULE_ID);
  }

  @Test
  public void testSearchByLastActivationTime() {
    insertTestRules();

    RuleSearchRequest searchRequest = RuleSearchRequest.builder()
        .lastActivationTime(new TimeInterval(
            Instant.ofEpochMilli(0), Instant.now()))
        .build();
    testSearch(searchRequest,
        FIRST_RULE_ID, SECOND_RULE_ID, THIRD_RULE_ID);

    searchRequest = RuleSearchRequest.builder()
        .lastActivationTime(new TimeInterval(
            Instant.ofEpochMilli(2), Instant.ofEpochMilli(11)))
        .includeDeletedRules(true)
        .build();
    testSearch(searchRequest, SECOND_RULE_ID);

    searchRequest = RuleSearchRequest.builder()
        .lastActivationTime(new TimeInterval(
            Instant.ofEpochMilli(14), Instant.now()))
        .build();
    testSearch(searchRequest);
  }

  @Override
  protected Searchable<RuleSearchRequest, RuleInfo, RuleSortField> searchable() {
    return ruleDao;
  }

  @Override
  protected Long getIdentifier(RuleInfo ruleInfo) {
    return ruleInfo.getId();
  }

  @Override
  protected RuleSortField defaultSortField() {
    return RuleSortField.ID;
  }

  private void insertTestRules() {
    RuleInfo ruleInfo1 = RuleInfo.builder()
        .setId(FIRST_RULE_ID)
        .setRuleText("file: path matches \"/src/*\" | read")
        .setSubmitTime(1)
        .setState(RuleState.NEW)
        .setLastCheckTime(0L)
        .build();

    ruleDao.insert(ruleInfo1);

    RuleInfo ruleInfo2 = RuleInfo.builder()
        .setId(SECOND_RULE_ID)
        .setRuleText("file: path matches \"/dist/*\" | copy -dest \"/\"")
        .setSubmitTime(2)
        .setState(RuleState.ACTIVE)
        .setLastCheckTime(2L)
        .build();

    ruleDao.insert(ruleInfo2);

    RuleInfo ruleInfo3 = RuleInfo.builder()
        .setId(THIRD_RULE_ID)
        .setRuleText("file: age > 10s | read")
        .setSubmitTime(12)
        .setState(RuleState.DISABLED)
        .setLastCheckTime(12L)
        .build();

    ruleDao.insert(ruleInfo3);

    RuleInfo ruleInfo4 = RuleInfo.builder()
        .setId(DELETED_RULE_ID)
        .setRuleText("file: path matches \"/tmp/*\" | write")
        .setSubmitTime(13)
        .setState(RuleState.DELETED)
        .setLastCheckTime(13L)
        .build();

    ruleDao.insert(ruleInfo4);
  }
}
