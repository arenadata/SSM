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
import org.smartdata.hdfs.scheduler.Copy2S3Scheduler;
import org.smartdata.hdfs.scheduler.CopyScheduler;
import org.smartdata.hive.action.HiveActionFactory;
import org.smartdata.hive.action.HmsSyncScheduler;
import org.smartdata.hive.rule.HmsSyncRulePlugin;
import org.smartdata.metastore.MetaStore;
import org.smartdata.model.action.ActionSchedulerService;
import org.smartdata.model.rule.RuleExecutorPlugin;
import org.smartdata.ozone.OzoneFetcherService;
import org.smartdata.ozone.action.OzoneActionFactory;
import org.smartdata.ozone.rule.OzoneSmartObjectSupplier;
import org.smartdata.rule.objects.SmartObjectSupplier;
import org.smartdata.server.engine.CmdletManager;
import org.smartdata.server.engine.ServerContext;
import org.smartdata.server.engine.file.CachedFilesManager;
import org.smartdata.server.engine.file.NoOpCachedFilesManager;
import org.smartdata.server.engine.rule.FileCopy2S3Plugin;
import org.smartdata.server.engine.rule.copy.FileCopyDrPlugin;
import org.smartdata.server.engine.rule.copy.FileCopyScheduleStrategy;
import org.smartdata.utils.ThrowingBiFunction;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;

public class OzoneFileSystemContext extends BaseFileSystemContext {
  @Override
  public List<RuleExecutorPlugin> ruleExecutorPlugins(ServerContext context, CmdletManager cmdletManager) {
    return Arrays.asList(
        new FileCopyDrPlugin(
            context.getMetaStore(), FileCopyScheduleStrategy.ordered()),
        new FileCopy2S3Plugin(),
        new HmsSyncRulePlugin(context.getMetaStore().hmsSyncProgressDao())
    );
  }

  @Override
  public List<ActionFactory> actionFactories() {
    return Arrays.asList(
        new OzoneActionFactory(),
        new HiveActionFactory()
    );
  }

  @Override
  public List<SmartService> additionalServices(ServerContext context) {
    OzoneFetcherService ozoneFetcherService = new OzoneFetcherService(
        context,
        context.getMetaStore().ozoneFileInfoDao()
    );

    return Collections.singletonList(ozoneFetcherService);
  }

  @Override
  public CachedFilesManager cachedFilesManager(ServerContext context) {
    return new NoOpCachedFilesManager();
  }

  @Override
  public SmartObjectSupplier smartObjectSupplier() {
    return new OzoneSmartObjectSupplier();
  }

  @Override
  protected Stream<ThrowingBiFunction<ServerContext,
      MetaStore, ActionSchedulerService>> actionSchedulerSuppliers() {
    return Stream.of(
        CopyScheduler::new,
        Copy2S3Scheduler::new,
        (ctx, metastore) -> new HmsSyncScheduler(ctx,
            metastore.hmsEventDao(), metastore.hmsSyncProgressDao()));
  }
}
