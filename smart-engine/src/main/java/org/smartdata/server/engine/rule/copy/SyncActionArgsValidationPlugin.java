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

import org.apache.commons.lang3.EnumUtils;
import org.apache.commons.lang3.StringUtils;
import org.smartdata.action.SyncAction;
import org.smartdata.exception.SsmParseException;
import org.smartdata.hdfs.action.PreserveAttribute;
import org.smartdata.model.CmdletDescriptor;
import org.smartdata.model.FileDiffType;
import org.smartdata.model.RuleInfo;
import org.smartdata.model.rule.RulePlugin;
import org.smartdata.model.rule.RulePluginManager;
import org.smartdata.model.rule.RuleTranslationResult;

import java.io.IOException;
import java.util.Arrays;
import java.util.Map;

import static org.smartdata.model.FileDiffType.FILTERABLE_DIFF_TYPES;

public class SyncActionArgsValidationPlugin implements RulePlugin {

  private static final SyncActionArgsValidationPlugin INSTANCE =
      new SyncActionArgsValidationPlugin();

  public static void register() {
    RulePluginManager.addPlugin(INSTANCE);
  }

  @Override
  public void onAddingNewRule(RuleInfo ruleInfo, RuleTranslationResult tr) throws IOException {
    CmdletDescriptor cmdletDescriptor = tr.getCmdDescriptor();
    for (int i = 0; i < cmdletDescriptor.getActionSize(); i++) {
      if (cmdletDescriptor.getActionName(i).equals(SyncAction.NAME)) {
        Map<String, String> args = cmdletDescriptor.getActionArgs(i);
        validateDiffTypeArg(SyncAction.INCLUDE, args.get(SyncAction.INCLUDE));
        validateDiffTypeArg(SyncAction.EXCLUDE, args.get(SyncAction.EXCLUDE));
        validatePreserveArg(args.get(SyncAction.PRESERVE));
      }
    }
  }

  @Override
  public void onNewRuleAdded(RuleInfo ruleInfo, RuleTranslationResult tr) {
  }

  private void validateDiffTypeArg(String argName, String argValue) throws IOException {
    if (argValue == null) {
      return;
    }
    validateArgNotBlank(argName, argValue);

    for (String rawType : argValue.split(",")) {
      String type = rawType.trim().toUpperCase();
      FileDiffType diffType = EnumUtils.getEnum(FileDiffType.class, type);
      if (diffType == null || !FileDiffType.isFilterable(diffType)) {
        throw new SsmParseException(
            "Invalid file filtering '" + type + "' in sync action '" + argName
                + "' argument. Valid values are: " + FILTERABLE_DIFF_TYPES);
      }
    }
  }

  private void validatePreserveArg(String argValue) throws IOException {
    if (argValue == null) {
      return;
    }
    validateArgNotBlank(SyncAction.PRESERVE, argValue);

    for (String rawAttribute : argValue.split(",")) {
      String attribute = rawAttribute.trim();
      if (!PreserveAttribute.isValidOption(attribute)) {
        throw new SsmParseException(
            "Invalid preserve attribute '" + attribute + "' in sync action '"
                + SyncAction.PRESERVE + "' argument. Valid values are: "
                + Arrays.toString(PreserveAttribute.values()));
      }
    }
  }

  private void validateArgNotBlank(String argName, String argValue) throws IOException {
    if (StringUtils.isBlank(argValue)) {
      throw new SsmParseException(
          "Empty value of sync action '" + argName + "' argument.");
    }
  }
}
