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
package org.smartdata.hive.action;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.smartdata.action.CmdletFactoryPlugin;
import org.smartdata.action.SmartAction;
import org.smartdata.conf.SmartConf;
import org.smartdata.hdfs.impersonation.UserImpersonationStrategy;
import org.smartdata.hive.client.CachingMetaStoreClientProvider;
import org.smartdata.hive.client.MetaStoreClientProvider;

import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
public class HmsCmdletFactoryPlugin implements CmdletFactoryPlugin {
  private final MetaStoreClientProvider hmsClientProvider;

  public HmsCmdletFactoryPlugin(SmartConf conf, UserImpersonationStrategy userImpersonationStrategy) {
    this.hmsClientProvider = new CachingMetaStoreClientProvider(conf, userImpersonationStrategy);
  }

  @Override
  public boolean canEnrich(SmartAction action) {
    return action instanceof HmsAction;
  }

  @Override
  public void enrichAction(SmartAction action, String actionUser) {
    if (!canEnrich(action)) {
      return;
    }

    HmsAction hmsAction = (HmsAction) action;
    hmsAction.setMetastoreClientSupplier(
        () -> hmsClientProvider.provide(actionUser, actionUser));
  }

  @Override
  public void close() throws IOException {

  }
}
