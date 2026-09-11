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

import org.apache.commons.lang3.EnumUtils;
import org.apache.commons.lang3.StringUtils;
import org.smartdata.exception.SsmParseException;
import org.smartdata.hive.action.HmsSyncAction;
import org.smartdata.hive.fetch.HiveOperation;
import org.smartdata.model.CmdletDescriptor;
import org.smartdata.model.RuleInfo;
import org.smartdata.model.rule.RulePlugin;
import org.smartdata.model.rule.RulePluginManager;
import org.smartdata.model.rule.RuleTranslationResult;

import java.io.IOException;
import java.util.Map;

public class HmsSyncOperationValidationPlugin implements RulePlugin {

  private static final HmsSyncOperationValidationPlugin INSTANCE =
      new HmsSyncOperationValidationPlugin();

  public static void register() {
    RulePluginManager.addPlugin(INSTANCE);
  }

  @Override
  public void onAddingNewRule(RuleInfo ruleInfo, RuleTranslationResult tr) throws IOException {
    CmdletDescriptor cmdletDescriptor = tr.getCmdDescriptor();
    for (int i = 0; i < cmdletDescriptor.getActionSize(); i++) {
      if (cmdletDescriptor.getActionName(i).equals(HmsSyncAction.NAME)) {
        Map<String, String> args = cmdletDescriptor.getActionArgs(i);
        validateOperationArg(HmsSyncAction.INCLUDE, args.get(HmsSyncAction.INCLUDE));
        validateOperationArg(HmsSyncAction.EXCLUDE, args.get(HmsSyncAction.EXCLUDE));
      }
    }
  }

  @Override
  public void onNewRuleAdded(RuleInfo ruleInfo, RuleTranslationResult tr) {
  }

  private void validateOperationArg(String argName, String argValue) throws IOException {
    if (argValue == null) {
      return;
    }
    validateArgNotBlank(argName, argValue);

    for (String rawOp : argValue.split(",")) {
      String operationName = rawOp.trim().toUpperCase();
      HiveOperation operation = EnumUtils.getEnum(HiveOperation.class, operationName);
      if (operation == null || !HiveOperation.isFilterable(operation)) {
        throw new SsmParseException(
            "Invalid or non-filterable HiveOperation '" + rawOp.trim() + "' in hms-sync action '"
                + argName + "' argument. Valid values are: " + HiveOperation.FILTERABLE_OPERATIONS);
      }
    }
  }

  private void validateArgNotBlank(String argName, String argValue) throws IOException {
    if (StringUtils.isBlank(argValue)) {
      throw new SsmParseException(
          "Empty value of hms-sync action '" + argName + "' argument.");
    }
  }
}
