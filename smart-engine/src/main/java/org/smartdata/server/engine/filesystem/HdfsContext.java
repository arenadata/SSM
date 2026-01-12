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
import org.smartdata.hdfs.HdfsStatesUpdateService;
import org.smartdata.hdfs.action.HdfsActionFactory;
import org.smartdata.hdfs.scheduler.CacheScheduler;
import org.smartdata.hdfs.scheduler.CompressionScheduler;
import org.smartdata.hdfs.scheduler.Copy2S3Scheduler;
import org.smartdata.hdfs.scheduler.CopyScheduler;
import org.smartdata.hdfs.scheduler.ErasureCodingScheduler;
import org.smartdata.hdfs.scheduler.MoverScheduler;
import org.smartdata.hdfs.scheduler.SmallFileScheduler;
import org.smartdata.hive.action.HiveActionFactory;
import org.smartdata.hive.action.HmsSyncScheduler;
import org.smartdata.hive.rule.HmsSyncRulePlugin;
import org.smartdata.metastore.MetaStore;
import org.smartdata.model.action.ActionSchedulerService;
import org.smartdata.model.rule.RuleExecutorPlugin;
import org.smartdata.server.engine.CmdletManager;
import org.smartdata.server.engine.ServerContext;
import org.smartdata.server.engine.file.CachedFilesManager;
import org.smartdata.server.engine.file.DbCachedFilesManager;
import org.smartdata.server.engine.rule.ErasureCodingPlugin;
import org.smartdata.server.engine.rule.FileCopy2S3Plugin;
import org.smartdata.server.engine.rule.SmallFilePlugin;
import org.smartdata.server.engine.rule.copy.FileCopyDrPlugin;
import org.smartdata.server.engine.rule.copy.FileCopyScheduleStrategy;
import org.smartdata.utils.ThrowingBiFunction;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;

public class HdfsContext extends BaseFileSystemContext {

  @Override
  public List<RuleExecutorPlugin> ruleExecutorPlugins(ServerContext context, CmdletManager cmdletManager) {
    return Arrays.asList(
        new FileCopyDrPlugin(
            context.getMetaStore(), FileCopyScheduleStrategy.ordered()),
        new FileCopy2S3Plugin(),
        new SmallFilePlugin(context, cmdletManager),
        new HmsSyncRulePlugin(context.getMetaStore().hmsSyncProgressDao()),
        new ErasureCodingPlugin(context));
  }

  @Override
  public List<ActionFactory> actionFactories() {
    return Arrays.asList(
        new HdfsActionFactory(),
        new HiveActionFactory()
    );
  }

  @Override
  public List<SmartService> additionalServices(ServerContext context) {
    HdfsStatesUpdateService statesUpdateService = new HdfsStatesUpdateService(
        context,
        context.getMetaStore());
    return Collections.singletonList(statesUpdateService);
  }

  @Override
  public CachedFilesManager cachedFilesManager(ServerContext context) {
    return new DbCachedFilesManager(context.getMetaStore().cacheFileDao());
  }

  @Override
  protected Stream<ThrowingBiFunction<
      ServerContext, MetaStore, ActionSchedulerService>> actionSchedulerSuppliers() {
    return Stream.of(
        (ctx, metastore) -> new MoverScheduler(ctx),
        CopyScheduler::new,
        Copy2S3Scheduler::new,
        SmallFileScheduler::new,
        CompressionScheduler::new,
        ErasureCodingScheduler::new,
        (ctx, metastore) -> new CacheScheduler(ctx),
        (ctx, metastore) -> new HmsSyncScheduler(ctx,
            metastore.hmsEventDao(), metastore.hmsSyncProgressDao()));
  }
}
