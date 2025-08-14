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
package org.smartdata.test.util.comparator;

import org.smartdata.test.model.ActionStatus;

import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;

import static org.smartdata.test.model.ActionStatus.FAILED;
import static org.smartdata.test.model.ActionStatus.RUNNING;
import static org.smartdata.test.model.ActionStatus.SCHEDULED;
import static org.smartdata.test.model.ActionStatus.SUCCESSFUL;

public class ActionStatusComparator implements Comparator<String> {

  private static final Map<ActionStatus, Integer> PRIORITY_MAP = new HashMap<>();

  static {
    PRIORITY_MAP.put(SCHEDULED, 1);
    PRIORITY_MAP.put(RUNNING, 2);
    PRIORITY_MAP.put(FAILED, 3);
    PRIORITY_MAP.put(SUCCESSFUL, 4);
  }

  @Override
  public int compare(String o1, String o2) {
    if (o1 == null || o2 == null) {
      throw new IllegalArgumentException("Arguments must not be null");
    }
    Integer priority1 = PRIORITY_MAP.get(ActionStatus.fromText(o1));
    Integer priority2 = PRIORITY_MAP.get(ActionStatus.fromText(o2));
    return priority1.compareTo(priority2);
  }
}
