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
package org.smartdata.hdfs.action;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.hadoop.hdfs.DistributedFileSystem;
import org.smartdata.action.ActionException;
import org.smartdata.action.CmdletFactoryPlugin;
import org.smartdata.action.SmartAction;
import org.smartdata.conf.SmartConf;
import org.smartdata.hdfs.client.CachingLocalFileSystemProvider;
import org.smartdata.hdfs.client.LocalFileSystemProvider;
import org.smartdata.hdfs.impersonation.UserImpersonationStrategy;

import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
public class HdfsCmdletFactoryPlugin implements CmdletFactoryPlugin {
  private final SmartConf conf;
  private final LocalFileSystemProvider localFileSystemProvider;

  public HdfsCmdletFactoryPlugin(SmartConf conf, UserImpersonationStrategy userImpersonationStrategy) {
    this.conf = conf;
    this.localFileSystemProvider = new CachingLocalFileSystemProvider(conf, userImpersonationStrategy);
  }

  @Override
  public boolean canEnrich(SmartAction action) {
    return action instanceof HdfsAction;
  }

  @Override
  public void enrichAction(SmartAction action, String actionUser) throws ActionException {
    if (!canEnrich(action)) {
      return;
    }

    HdfsAction hdfsAction = (HdfsAction) action;
    setLocalFileSystem(hdfsAction, actionUser);
  }

  private void setLocalFileSystem(HdfsAction action, String actionUser) throws ActionException {
    try {
      DistributedFileSystem localFileSystem = localFileSystemProvider.provide(
          conf, actionUser, action.localFsType());
      action.setLocalFileSystem(localFileSystem);
    } catch (IOException exception) {
      log.error("smartAction aid={} setDfsClient error", action.getActionId(), exception);
      throw new ActionException(exception);
    }
  }

  @Override
  public void close() throws IOException {
    localFileSystemProvider.close();
  }
}
