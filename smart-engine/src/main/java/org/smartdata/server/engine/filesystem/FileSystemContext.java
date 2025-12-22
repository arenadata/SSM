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
package org.smartdata.server.engine.filesystem;

import org.smartdata.SmartService;
import org.smartdata.action.ActionFactory;
import org.smartdata.conf.SmartConf;
import org.smartdata.conf.SmartFsType;
import org.smartdata.model.action.ActionSchedulerService;
import org.smartdata.model.rule.RuleExecutorPlugin;
import org.smartdata.server.engine.CmdletManager;
import org.smartdata.server.engine.ServerContext;
import org.smartdata.server.engine.file.CachedFilesManager;

import java.util.List;

public interface FileSystemContext {
  List<ActionSchedulerService> actionSchedulerServices(ServerContext context);

  List<RuleExecutorPlugin> ruleExecutorPlugins(
      ServerContext context,
      CmdletManager cmdletManager);

  List<ActionFactory> actionFactories();

  List<SmartService> additionalServices(ServerContext context);

  CachedFilesManager cachedFilesManager(ServerContext context);

  static FileSystemContext fromConfig(SmartConf conf) {
    return fromFsType(conf.getFsType());
  }

  static FileSystemContext fromFsType(SmartFsType fsType) {
    return fsType == SmartFsType.HDFS
        ? new HdfsContext()
        : new OzoneFileSystemContext();
  }
}
