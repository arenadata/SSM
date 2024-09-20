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
package org.smartdata.server.engine.cmdlet;

import org.smartdata.model.CmdletDescriptor;

import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Track CmdletDescriptor from the submission of the corresponding Cmdlet to
 * the finish of that Cmdlet. CmdletDescriptor defines a task and it is wrapped
 * by Cmdlet or CmdletInfo to
 */
public class RuleCmdletTracker {
  // Contains CmdletDescriptor being tackled.
  private final Set<CmdletDescriptor> cmdletDescriptors;
  // The ID of a submitted cmdlet to the corresponding CmdletDescriptor.
  private final Map<Long, CmdletDescriptor> idToDescriptor;

  public RuleCmdletTracker() {
    this.cmdletDescriptors = ConcurrentHashMap.newKeySet();
    this.idToDescriptor = new ConcurrentHashMap<>();
  }

  /**
   * Start tracking the CmdletDescriptor which is wrapped by a executable
   * cmdlet whose ID is cmdletId.
   **/
  public void track(long cmdletId, CmdletDescriptor cmdletDescriptor) {
    cmdletDescriptors.add(cmdletDescriptor);
    idToDescriptor.put(cmdletId, cmdletDescriptor);
  }

  /**
   * Untrack the CmdletDescriptor when the corresponding Cmdlet is finished.
   * @param cmdletId the ID of the finished Cmdlet.
   */
  public void stopTracking(long cmdletId) {
    Optional.ofNullable(idToDescriptor.remove(cmdletId))
        .ifPresent(cmdletDescriptors::remove);
  }

  /**
   * Used to avoid repeatedly submitting cmdlet for same CmdletDescriptor.
   */
  public boolean contains(CmdletDescriptor cmdletDescriptor) {
    return cmdletDescriptors.contains(cmdletDescriptor);
  }
}
