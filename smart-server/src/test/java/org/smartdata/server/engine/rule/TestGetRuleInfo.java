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

import org.junit.Assert;
import org.junit.Test;
import org.smartdata.admin.SmartAdmin;
import org.smartdata.model.RuleInfo;
import org.smartdata.model.RuleState;
import org.smartdata.server.MiniSmartClusterHarness;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class TestGetRuleInfo extends MiniSmartClusterHarness {

  @Test
  public void testGetSingleRuleInfo() throws Exception {
    waitTillSSMExitSafeMode();

    String rule = "file: every 1s \n | length > 10 | cache";
    try (SmartAdmin client = new SmartAdmin(smartContext.getConf())) {

      long ruleId = client.submitRule(rule, RuleState.ACTIVE);
      RuleInfo info1 = client.getRuleInfo(ruleId);
      System.out.println(info1);
      Assert.assertEquals(info1.getRuleText(), rule);

      RuleInfo infoTemp = info1;
      for (int i = 0; i < 3; i++) {
        Thread.sleep(1000);
        infoTemp = client.getRuleInfo(ruleId);
        System.out.println(infoTemp);
      }
      Assert.assertTrue(infoTemp.getNumChecked() >= info1.getNumChecked() + 2);

      long fakeRuleId = 10999999999L;
      try {
        client.getRuleInfo(fakeRuleId);
        Assert.fail("Should raise an exception when using a invalid rule id");
      } catch (IOException e) {
      }

      client.deleteRule(ruleId, true);
    }
  }

  @Test
  public void testMultiRules() throws Exception {
    waitTillSSMExitSafeMode();

    String rule = "file: every 1s \n | length > 10 | cache";
    int nRules;
    List<RuleInfo> ruleInfos;
    try (SmartAdmin client = new SmartAdmin(smartContext.getConf())) {

      List<Long> ruleIds = new ArrayList<>();
      nRules = 10;
      for (int i = 0; i < nRules; i++) {
        long ruleId = client.submitRule(rule, RuleState.ACTIVE);
        ruleIds.add(ruleId);
      }

      ruleInfos = client.listRulesInfo();
      for (RuleInfo info : ruleInfos) {
        System.out.println(info);
      }
      Assert.assertEquals(ruleInfos.size(), nRules);

      for (long ruleId : ruleIds) {
        client.deleteRule(ruleId, true);
      }
    }
  }
}
