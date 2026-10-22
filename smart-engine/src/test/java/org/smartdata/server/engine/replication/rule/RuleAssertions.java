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
package org.smartdata.server.engine.replication.rule;

import org.smartdata.conf.SmartConf;
import org.smartdata.hive.rule.HmsSyncOperationValidationPlugin;
import org.smartdata.model.rule.RuleTranslationResult;
import org.smartdata.rule.parser.SmartRuleStringParser;
import org.smartdata.server.engine.rule.copy.SyncActionArgsValidationPlugin;

import java.util.List;

import static org.junit.Assert.assertEquals;

final class RuleAssertions {

  /**
   * Asserts the rendered rules and checks that they are accepted by the rule parser
   * and the sync/hms-sync action arguments validation.
   */
  static void assertRules(RuleGenerationResult result, String... expectedRules)
      throws Exception {
    List<String> rules = result.renderRules();
    assertEquals(List.of(expectedRules), rules);

    for (String rule : rules) {
      RuleTranslationResult translationResult =
          new SmartRuleStringParser(rule, null, new SmartConf()).translate();
      new SyncActionArgsValidationPlugin().onAddingNewRule(null, translationResult);
      new HmsSyncOperationValidationPlugin().onAddingNewRule(null, translationResult);
    }
  }
}
