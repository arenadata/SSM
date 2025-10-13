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
package org.smartdata.hdfs.impersonation;

import org.smartdata.conf.SmartConf;

import static org.smartdata.conf.SmartConfKeys.SMART_PROXY_USER_STRATEGY_KEY;

public class UserImpersonationStrategyFactory {
  public static UserImpersonationStrategy from(SmartConf conf) {
    UserImpersonationStrategy.Scope impersonationScope = conf.getEnum(
        SMART_PROXY_USER_STRATEGY_KEY, UserImpersonationStrategy.Scope.DISABLED);
    switch (impersonationScope) {
      case NODE_SCOPE:
        return ExplicitUserImpersonationStrategy.from(conf);
      case CMDLET_SCOPE:
        return CmdletOwnerUserImpersonationStrategy.from(conf);
      default:
        return new DisabledUserImpersonationStrategy();
    }
  }
}
