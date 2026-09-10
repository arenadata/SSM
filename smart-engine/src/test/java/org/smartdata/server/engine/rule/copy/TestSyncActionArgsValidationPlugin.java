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
package org.smartdata.server.engine.rule.copy;

import org.junit.Assert;
import org.junit.Test;
import org.smartdata.action.SyncAction;
import org.smartdata.cmdlet.parser.ParsedCmdlet;
import org.smartdata.hdfs.action.PreserveAttribute;
import org.smartdata.model.CmdletDescriptor;
import org.smartdata.model.FileDiffType;
import org.smartdata.model.rule.RuleTranslationResult;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class TestSyncActionArgsValidationPlugin {

  private final SyncActionArgsValidationPlugin plugin =
      new SyncActionArgsValidationPlugin();

  @Test
  public void noSyncAction() throws IOException {
    plugin.onAddingNewRule(null, translationResultWith("cache"));
  }

  @Test
  public void syncActionNoOptionalArgs() throws IOException {
    plugin.onAddingNewRule(null, translationResultWith(SyncAction.NAME));
  }

  @Test
  public void syncActionWithValidInclude() throws IOException {
    plugin.onAddingNewRule(null, translationResultWith(
        SyncAction.NAME,
        SyncAction.INCLUDE, "CREATE,APPEND"));
  }

  @Test
  public void syncActionWithValidExclude() throws IOException {
    plugin.onAddingNewRule(null, translationResultWith(
        SyncAction.NAME,
        SyncAction.EXCLUDE, "DELETE,RENAME"));
  }

  @Test
  public void syncActionWithAllValidDiffTypes() throws IOException {
    String allTypes = FileDiffType.FILTERABLE_DIFF_TYPES.stream()
        .map(Enum::name)
        .collect(Collectors.joining(","));
    plugin.onAddingNewRule(null, translationResultWith(
        SyncAction.NAME,
        SyncAction.INCLUDE, allTypes));
  }

  @Test
  public void syncActionWithInvalidInclude() {
    Assert.assertThrows(IOException.class, () -> plugin.onAddingNewRule(null, translationResultWith(
        SyncAction.NAME,
        SyncAction.INCLUDE, "INVALID_TYPE")));
  }

  @Test
  public void syncActionWithInvalidExclude() {
    Assert.assertThrows(IOException.class, () -> plugin.onAddingNewRule(null, translationResultWith(
        SyncAction.NAME,
        SyncAction.EXCLUDE, "CREATE,BAD_TYPE")));
  }

  @Test
  public void syncActionWithInvalidIncludeAmongMultiple() {
    Assert.assertThrows(IOException.class, () -> plugin.onAddingNewRule(null, translationResultWith(
        SyncAction.NAME,
        SyncAction.INCLUDE, "CREATE,UNKNOWN,APPEND")));
  }

  @Test
  public void syncActionWithUnfilterableDiffType() {
    Assert.assertThrows(IOException.class, () -> plugin.onAddingNewRule(null, translationResultWith(
        SyncAction.NAME,
        SyncAction.INCLUDE, FileDiffType.BASESYNC.name())));
  }

  @Test
  public void syncActionWithBothValidIncludeAndExclude() throws IOException {
    plugin.onAddingNewRule(null, translationResultWith(
        SyncAction.NAME,
        SyncAction.INCLUDE, "CREATE,APPEND",
        SyncAction.EXCLUDE, "DELETE,RENAME"));
  }

  @Test
  public void syncActionWithValidIncludeAndInvalidExclude() {
    Assert.assertThrows(IOException.class, () -> plugin.onAddingNewRule(null, translationResultWith(
        SyncAction.NAME,
        SyncAction.INCLUDE, "CREATE",
        SyncAction.EXCLUDE, "BAD_TYPE")));
  }

  @Test
  public void syncActionWithInvalidIncludeAndValidExclude() {
    Assert.assertThrows(IOException.class, () -> plugin.onAddingNewRule(null, translationResultWith(
        SyncAction.NAME,
        SyncAction.INCLUDE, "BAD_TYPE",
        SyncAction.EXCLUDE, "DELETE")));
  }

  @Test
  public void syncActionWithValidPreserve() throws IOException {
    plugin.onAddingNewRule(null, translationResultWith(
        SyncAction.NAME,
        SyncAction.PRESERVE, "owner,group"));
  }

  @Test
  public void syncActionWithAllValidPreserveAttributes() throws IOException {
    String allAttributes = Arrays.stream(PreserveAttribute.values())
        .map(PreserveAttribute::toString)
        .collect(Collectors.joining(","));
    plugin.onAddingNewRule(null, translationResultWith(
        SyncAction.NAME,
        SyncAction.PRESERVE, allAttributes));
  }

  @Test
  public void syncActionWithBlankPreserve() throws IOException {
    plugin.onAddingNewRule(null, translationResultWith(
        SyncAction.NAME,
        SyncAction.PRESERVE, "  "));
  }

  @Test
  public void syncActionWithInvalidPreserve() {
    Assert.assertThrows(IOException.class, () -> plugin.onAddingNewRule(null, translationResultWith(
        SyncAction.NAME,
        SyncAction.PRESERVE, "INCORRECT")));
  }

  @Test
  public void syncActionWithInvalidPreserveAmongMultiple() {
    Assert.assertThrows(IOException.class, () -> plugin.onAddingNewRule(null, translationResultWith(
        SyncAction.NAME,
        SyncAction.PRESERVE, "owner,BAD_ATTRIBUTE,group")));
  }

  @Test
  public void syncActionWithDifferentCasePreserve() throws IOException {
    plugin.onAddingNewRule(null, translationResultWith(
        SyncAction.NAME,
        SyncAction.PRESERVE, "OWNER,Group,Modification-Time"));
  }

  @Test
  public void syncActionWithValidExcludeAndInvalidPreserve() {
    Assert.assertThrows(IOException.class, () -> plugin.onAddingNewRule(null, translationResultWith(
        SyncAction.NAME,
        SyncAction.EXCLUDE, "DELETE",
        SyncAction.PRESERVE, "INCORRECT")));
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
