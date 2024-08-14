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
package org.smartdata.metastore.accesscount.failover;

import lombok.RequiredArgsConstructor;
import org.smartdata.conf.SmartConf;
import org.smartdata.metastore.accesscount.failover.impl.RetryAccessCountFailover;

import static org.smartdata.conf.SmartConfKeys.SMART_ACCESS_COUNT_AGGREGATOR_FAILOVER_KEY;
import static org.smartdata.conf.SmartConfKeys.SMART_ACCESS_COUNT_AGGREGATOR_FAILOVER_MAX_RETRIES_DEFAULT;
import static org.smartdata.conf.SmartConfKeys.SMART_ACCESS_COUNT_AGGREGATOR_FAILOVER_MAX_RETRIES_KEY;

@RequiredArgsConstructor
public class AccessCountFailoverFactory {
  private final SmartConf conf;

  public Failover<AccessCountContext> create() {
    Failover.Strategy failoverStrategy =
        conf.getEnum(SMART_ACCESS_COUNT_AGGREGATOR_FAILOVER_KEY, Failover.Strategy.FAIL);
    switch (failoverStrategy) {
      case FAIL:
        return new Failover<AccessCountContext>() {
        };
      case SAVE_FAILED_WITH_RETRY:
      default:
        int maxRetries = conf.getInt(SMART_ACCESS_COUNT_AGGREGATOR_FAILOVER_MAX_RETRIES_KEY,
            SMART_ACCESS_COUNT_AGGREGATOR_FAILOVER_MAX_RETRIES_DEFAULT);
        return new RetryAccessCountFailover(maxRetries);
    }
  }
}
