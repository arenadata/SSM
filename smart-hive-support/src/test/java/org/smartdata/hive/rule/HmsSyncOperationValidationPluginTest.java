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
package org.smartdata.hive.rule;

import org.junit.Assert;
import org.junit.Test;
import org.smartdata.cmdlet.parser.ParsedCmdlet;
import org.smartdata.hive.action.HmsSyncAction;
import org.smartdata.hive.fetch.HiveOperation;
import org.smartdata.model.CmdletDescriptor;
import org.smartdata.model.rule.RuleTranslationResult;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class HmsSyncOperationValidationPluginTest {

  private final HmsSyncOperationValidationPlugin plugin =
      new HmsSyncOperationValidationPlugin();

  @Test
  public void noHmsSyncAction() throws IOException {
    plugin.onAddingNewRule(null, translationResultWith("cache"));
  }

  @Test
  public void hmsSyncActionNoIncludeExcludeArgs() throws IOException {
    plugin.onAddingNewRule(null, translationResultWith(HmsSyncAction.NAME));
  }

  @Test
  public void hmsSyncActionWithValidInclude() throws IOException {
    plugin.onAddingNewRule(null, translationResultWith(
        HmsSyncAction.NAME,
        HmsSyncAction.INCLUDE, "CREATE,DROP"));
  }

  @Test
  public void hmsSyncActionWithValidExclude() throws IOException {
    plugin.onAddingNewRule(null, translationResultWith(
        HmsSyncAction.NAME,
        HmsSyncAction.EXCLUDE, "ALTER"));
  }

  @Test
  public void hmsSyncActionWithAllFilterableOperations() throws IOException {
    String allFilterable = HiveOperation.FILTERABLE_OPERATIONS.stream()
        .map(Enum::name)
        .collect(Collectors.joining(","));
    plugin.onAddingNewRule(null, translationResultWith(
        HmsSyncAction.NAME,
        HmsSyncAction.INCLUDE, allFilterable));
  }

  @Test
  public void hmsSyncActionWithBothValidIncludeAndExclude() throws IOException {
    plugin.onAddingNewRule(null, translationResultWith(
        HmsSyncAction.NAME,
        HmsSyncAction.INCLUDE, "CREATE",
        HmsSyncAction.EXCLUDE, "DROP,ALTER"));
  }

  @Test
  public void hmsSyncActionWithInvalidInclude() {
    Assert.assertThrows(IOException.class, () -> plugin.onAddingNewRule(null, translationResultWith(
        HmsSyncAction.NAME,
        HmsSyncAction.INCLUDE, "INVALID_OP")));
  }

  @Test
  public void hmsSyncActionWithInvalidExclude() {
    Assert.assertThrows(IOException.class, () -> plugin.onAddingNewRule(null, translationResultWith(
        HmsSyncAction.NAME,
        HmsSyncAction.EXCLUDE, "CREATE,BAD_OP")));
  }

  @Test
  public void hmsSyncActionWithNonFilterableOperation() {
    // UNKNOWN is a valid HiveOperation enum value but not filterable
    Assert.assertThrows(IOException.class, () -> plugin.onAddingNewRule(null, translationResultWith(
        HmsSyncAction.NAME,
        HmsSyncAction.INCLUDE, "UNKNOWN")));
  }

  @Test
  public void hmsSyncActionWithValidIncludeAndInvalidExclude() {
    Assert.assertThrows(IOException.class, () -> plugin.onAddingNewRule(null, translationResultWith(
        HmsSyncAction.NAME,
        HmsSyncAction.INCLUDE, "CREATE",
        HmsSyncAction.EXCLUDE, "BAD_OP")));
  }

  @Test
  public void hmsSyncActionWithInvalidIncludeAndValidExclude() {
    Assert.assertThrows(IOException.class, () -> plugin.onAddingNewRule(null, translationResultWith(
        HmsSyncAction.NAME,
        HmsSyncAction.INCLUDE, "BAD_OP",
        HmsSyncAction.EXCLUDE, "DROP")));
  }

  private RuleTranslationResult translationResultWith(String actionName, String... args) {
    Map<String, String> argsMap = new HashMap<>();
    for (int i = 0; i + 1 < args.length; i += 2) {
      argsMap.put(args[i], args[i + 1]);
    }
    CmdletDescriptor cmdletDescriptor = new CmdletDescriptor(
        ParsedCmdlet.newBuilder()
            .addAction(actionName, argsMap)
            .build());
    RuleTranslationResult tr = mock(RuleTranslationResult.class);
    when(tr.getCmdDescriptor()).thenReturn(cmdletDescriptor);
    return tr;
  }
}
