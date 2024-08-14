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
package org.smartdata.metastore.accesscount.failover.impl;

import lombok.RequiredArgsConstructor;
import org.smartdata.metastore.accesscount.failover.AccessCountContext;
import org.smartdata.metastore.accesscount.failover.Failover;
import org.smartdata.metastore.accesscount.failover.Statement;
import org.smartdata.metastore.model.AggregatedAccessCounts;

import java.util.ArrayList;
import java.util.List;

@RequiredArgsConstructor
public class RetryAccessCountFailover implements Failover<AccessCountContext> {
  private final List<AggregatedAccessCounts> failedAccessCounts = new ArrayList<>();
  private final int maxRetries;
  private int retryCount = 0;

  @Override
  public void execute(Statement<AccessCountContext> statement, AccessCountContext context) {
    try {
      if (!failedAccessCounts.isEmpty()) {
        List<AggregatedAccessCounts> accessCounts = new ArrayList<>(context.getAccessCounts());
        accessCounts.addAll(failedAccessCounts);
        context = new AccessCountContext(accessCounts);
      }
      statement.execute(context);
      resetRetries();
    } catch (Exception e) {
      retryCount++;
      if (retryCount < maxRetries + 1) {
        failedAccessCounts.addAll(context.getAccessCounts());
      } else {
        resetRetries();
        throw new RuntimeException(e);
      }
    }
  }

  private void resetRetries() {
    retryCount = 0;
    failedAccessCounts.clear();
  }
}
