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

import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.util.Arrays;
import java.util.List;

/**
 * The possible state that a cmdlet can be in.
 */
@RequiredArgsConstructor
@Getter
public enum CmdletState {
  NOTINITED(0),
  PENDING(1), // Ready for schedule
  SCHEDULED(2),
  DISPATCHED(3),
  EXECUTING(4), // Still running
  PAUSED(5),
  CANCELLED(7),
  DISABLED(8), // Disable this Cmdlet, kill all executing actions
  FAILED(9),   // Running cmdlet failed
  DONE(10); // Execution successful

  private final int value;

  public static CmdletState fromValue(int value) {
    for (CmdletState r : values()) {
      if (value == r.getValue()) {
        return r;
      }
    }
    return null;
  }

  public static boolean isTerminalState(CmdletState state) {
    return getTerminalStates().contains(state);
  }

  public static List<CmdletState> getTerminalStates() {
    return Arrays.asList(CANCELLED, DISABLED, FAILED, DONE);
  }

  @Override
  public String toString() {
    return String.format("CmdletState{value=%s} %s", value, super.toString());
  }
}
