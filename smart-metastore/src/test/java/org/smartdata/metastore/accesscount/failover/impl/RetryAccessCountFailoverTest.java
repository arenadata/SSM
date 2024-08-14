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

import org.junit.Test;
import org.smartdata.metastore.accesscount.failover.AccessCountContext;
import org.smartdata.metastore.accesscount.failover.Failover;
import org.smartdata.metastore.model.AggregatedAccessCounts;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

public class RetryAccessCountFailoverTest {
  private Failover<AccessCountContext> accessCountFailover;

  @Test
  public void testExecuteWithoutExceedingOverMaxRetries() {
    int maxRetries = 3;
    int attemptsCount = 0;
    long currentTimeMillis = System.currentTimeMillis();
    accessCountFailover = new RetryAccessCountFailover(maxRetries);
    List<AggregatedAccessCounts> accessCounts = new ArrayList<>(Collections.singletonList(
        new AggregatedAccessCounts(1, 1, currentTimeMillis)));
    AccessCountContext context = new AccessCountContext(accessCounts);
    for (int i = 1; i <= maxRetries; i++) {
      accessCountFailover.execute(ctx -> {
        throw new RuntimeException("error");
      }, context);
      attemptsCount = i;
    }
    assertEquals(maxRetries, attemptsCount);
  }

  @Test
  public void testExecuteWithExceedingOverMaxRetries() {
    RuntimeException error = new RuntimeException("error");
    int maxRetries = 3;
    long currentTimeMillis = System.currentTimeMillis();
    accessCountFailover = new RetryAccessCountFailover(maxRetries);
    List<AggregatedAccessCounts> accessCounts = new ArrayList<>(Collections.singletonList(
        new AggregatedAccessCounts(1, 1, currentTimeMillis)));
    AccessCountContext context = new AccessCountContext(accessCounts);
    assertThrows(RuntimeException.class, () -> {
      for (int i = 1; i <= maxRetries + 1; i++) {
        accessCountFailover.execute(ctx -> {
          throw error;
        }, context);
      }
    });
  }
}
