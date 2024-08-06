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

import java.util.ArrayList;
import java.util.List;

@Data
@AllArgsConstructor
@Builder(setterPrefix = "set")
public class CmdletInfo {
  private long id;
  private long ruleId;
  @lombok.Builder.Default
  private List<Long> actionIds = new ArrayList<>();
  private CmdletState state;
  private String parameters;
  private final long generateTime;
  private long stateChangedTime;

  public CmdletInfo(
      long id,
      long ruleId,
      CmdletState state,
      String parameters,
      long generateTime,
      long stateChangedTime) {
    this(id, ruleId, new ArrayList<>(), state,
        parameters, generateTime, stateChangedTime);
  }

  @Override
  public String toString() {
    return String.format("CmdletId -> [ %s ] {rid = %d, aids = %s, genTime = %d, "
            + "stateChangedTime = %d, state = %s, params = %s}",
        id, ruleId, actionIds,
        generateTime, stateChangedTime, state,
        parameters);
  }

  public void addAction(long aid) {
    actionIds.add(aid);
  }

  public void updateState(CmdletState state) {
    if (this.state != state) {
      this.state = state;
      this.stateChangedTime = System.currentTimeMillis();
    }
  }
}
