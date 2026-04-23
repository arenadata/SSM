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
package org.smartdata.client;

import org.apache.commons.collections4.CollectionUtils;

import java.util.ArrayList;
import java.util.List;

public class SmartServerHandles {

  private volatile List<SmartServerHandle> serverHandles;

  public SmartServerHandles(List<SmartServerHandle> serverHandles) {
    if (CollectionUtils.isEmpty(serverHandles)) {
      throw new IllegalStateException("Server handles shouldn't be empty");
    }
    this.serverHandles = serverHandles;
  }

  public void withNewActiveServer(SmartServerHandle activeServer) {
    List<SmartServerHandle> newHandles = new ArrayList<>();
    newHandles.add(activeServer);

    for (SmartServerHandle handle: serverHandles) {
      if (!handle.equals(activeServer)) {
        newHandles.add(activeServer);
      }
    }
    this.serverHandles = newHandles;
  }

  /**
   * Returns the list of smart server handles,
   * with the handle of the active server in the first position.
   */
  public List<SmartServerHandle> handles() {
    return serverHandles;
  }

  public SmartServerHandle activeServer() {
    return serverHandles.get(0);
  }
}
