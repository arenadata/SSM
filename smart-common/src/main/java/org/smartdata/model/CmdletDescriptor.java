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
package org.smartdata.model;

import org.smartdata.cmdlet.parser.ParsedAction;
import org.smartdata.cmdlet.parser.ParsedCmdlet;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.smartdata.utils.FormattingUtil.actionToString;

/**
 * CmdletDescriptor describes a cmdlet by parsing out action names and their
 * parameters like shell format. It does not including verifications like
 * whether the action is supported or the parameters are valid or not.
 *
 * <p>Cmdlet string should have the following format:
 *    action1 [-option [value]] ... [; action2 [-option [value]] ...]
 */
public class CmdletDescriptor {
  public static final String RULE_ID = "-ruleId";
  public static final String HDFS_FILE_PATH = "-file";

  private final List<String> actionNames;
  private final Map<String, String> actionCommonArgs;
  private final List<Map<String, String>> actionArgs;
  private String cmdletString;

  public CmdletDescriptor(ParsedCmdlet parsedCmdlet) {
    this.cmdletString = parsedCmdlet.getCmdletString();
    this.actionNames = new ArrayList<>();
    this.actionCommonArgs = new HashMap<>();
    this.actionArgs = new ArrayList<>();

    parsedCmdlet.getActions().forEach(this::addAction);
  }

  public CmdletDescriptor(CmdletDescriptor other) {
    this.cmdletString = other.getCmdletString();
    this.actionNames = new ArrayList<>(other.actionNames);
    this.actionCommonArgs = new HashMap<>(other.actionCommonArgs);
    this.actionArgs = other.actionArgs
        .stream()
        .map(HashMap::new)
        .collect(Collectors.toList());
  }

  public String getCmdletString() {
    return cmdletString == null ? toCmdletString() : cmdletString;
  }

  public void setCmdletParameter(String key, String value) {
    actionCommonArgs.put(key, value);
    // After the setting, the cmdlet string should be changed.
    this.cmdletString = toCmdletString();
  }

  public long getRuleId() {
    String idStr = actionCommonArgs.get(RULE_ID);
    try {
      return idStr == null ? 0 : Long.parseLong(idStr);
    } catch (Exception e) {
      return 0;
    }
  }

  public void setRuleId(long ruleId) {
    actionCommonArgs.put(RULE_ID, String.valueOf(ruleId));
  }

  public boolean isRuleCmdlet() {
    return actionCommonArgs.containsKey(RULE_ID);
  }

  public List<String> getActionNames() {
    List<String> ret = new ArrayList<>(actionNames.size());
    ret.addAll(actionNames);
    return ret;
  }

  public String getActionName(int index) {
    return actionNames.get(index);
  }

  /**
   * Get a complete set of arguments including cmdlet common part.
   */
  public Map<String, String> getActionArgs(int index) {
    Map<String, String> map = new HashMap<>();
    map.putAll(actionCommonArgs);
    map.putAll(actionArgs.get(index));
    return map;
  }

  public void addActionArg(int index, String key, String value) {
    actionArgs.get(index).put(key, value);
  }

  public int getActionSize() {
    return actionNames.size();
  }

  public String toCmdletString() {
    return IntStream.range(0, getActionSize())
        .mapToObj(i -> actionToString(getActionName(i), getActionArgs(i)))
        .collect(Collectors.joining(" ; "));
  }

  public boolean equals(CmdletDescriptor des) {
    if (des == null || this.getActionSize() != des.getActionSize()) {
      return false;
    }

    for (int i = 0; i < this.getActionSize(); i++) {
      if (!actionNames.get(i).equals(des.getActionName(i))) {
        return false;
      }

      Map<String, String> srcArgs = getActionArgs(i);
      Map<String, String> destArgs = des.getActionArgs(i);

      if (srcArgs.size() != destArgs.size()) {
        return false;
      }

      for (String key : srcArgs.keySet()) {
        if (!srcArgs.get(key).equals(destArgs.get(key))) {
          return false;
        }
      }
    }
    return true;
  }

  @Override
  public String toString() {
    return String.format(
        "CmdletDescriptor{actionCommon=%s, actionNames=%s, "
            + "actionArgs=%s, cmdletString='%s'}",
        actionCommonArgs, actionNames, actionArgs, cmdletString);
  }

  /**
   * To judge whether a same task is being tackled by SSM, we override
   * #hashCode and #equals to give this logical equal meaning: one ojbect
   * equals another if they have the same rule ID and same cmdlet string.
   */
  @Override
  public int hashCode() {
    return Objects.hash(getRuleId(), getCmdletString());
  }

  @Override
  public boolean equals(Object o) {
    if (o == null || this.getClass() != o.getClass()) {
      return false;
    }
    if (this == o) {
      return true;
    }
    CmdletDescriptor another = (CmdletDescriptor) o;
    return this.getRuleId() == another.getRuleId()
        && this.getCmdletString().equals(another.getCmdletString());
  }

  public static List<String> toArgList(Map<String, String> args) {
    List<String> ret = new ArrayList<>();
    for (String key : args.keySet()) {
      ret.add(key);
      ret.add(args.get(key));
    }
    return ret;
  }

  private void addAction(ParsedAction parsedAction) {
    actionNames.add(parsedAction.getName());
    actionArgs.add(parsedAction.getArgs());
  }
}
