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

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Optional;

/**
 * Contains info about a rule inside SSM.
 */
@Data
@AllArgsConstructor
@Builder(setterPrefix = "set")
public class RuleInfo {
  private long id;
  private long submitTime;
  private String ruleText;
  private RuleState state;

  // Some static information about rule
  private long numChecked;
  private long numCmdsGen;
  private Long lastCheckTime;
  private String owner;

  public void updateRuleInfo(RuleState rs, long lastCheckTime,
      long checkedCount, int cmdletsGen) {
    if (rs != null) {
      this.state = rs;
    }
    if (lastCheckTime != 0) {
      this.lastCheckTime = lastCheckTime;
    }
    this.numChecked += checkedCount;
    this.numCmdsGen += cmdletsGen;
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss");
    Date submitDate = new Date(submitTime);
    String lastCheck = Optional.ofNullable(lastCheckTime)
        .filter(time -> time != 0)
        .map(Date::new)
        .map(sdf::format)
        .orElse("Not Checked");

    sb.append("{ id = ")
        .append(id)
        .append(", submitTime = '")
        .append(sdf.format(submitDate))
        .append("'")
        .append(", State = ")
        .append(state.toString())
        .append(", lastCheckTime = '")
        .append(lastCheck)
        .append("'")
        .append(", numChecked = ")
        .append(numChecked)
        .append(", numCmdsGen = ")
        .append(numCmdsGen)
        .append(" }");
    return sb.toString();
  }

  public RuleInfo newCopy() {
    return new RuleInfo(id, submitTime, ruleText, state, numChecked,
        numCmdsGen, lastCheckTime, owner);
  }
}
