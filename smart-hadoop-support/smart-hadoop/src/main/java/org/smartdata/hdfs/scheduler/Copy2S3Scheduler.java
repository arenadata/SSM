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
package org.smartdata.hdfs.scheduler;

import org.apache.hadoop.conf.Configuration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.smartdata.SmartContext;
import org.smartdata.hdfs.action.HdfsAction;
import org.smartdata.metastore.MetaStore;
import org.smartdata.metastore.MetaStoreException;
import org.smartdata.model.ActionInfo;
import org.smartdata.model.CmdletInfo;
import org.smartdata.model.FileState;
import org.smartdata.model.LaunchAction;
import org.smartdata.model.S3FileState;
import org.smartdata.model.action.ScheduleResult;
import org.smartdata.protocol.message.LaunchCmdlet;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;


public class Copy2S3Scheduler extends ActionSchedulerService {
  private static final List<String> actions = Arrays.asList("copy2s3");
  static final Logger LOG =
      LoggerFactory.getLogger(Copy2S3Scheduler.class);
  private MetaStore metaStore;
  //The file in copy need to be locked
  private Set<String> fileLock;
  // Global variables
  private Configuration conf;

  public Copy2S3Scheduler(SmartContext context, MetaStore metaStore) {
    super(context, metaStore);
    this.metaStore = metaStore;
    this.fileLock = Collections.synchronizedSet(new HashSet<String>());
    try {
      this.conf = getContext().getConf();
    } catch (NullPointerException e) {
      // If SmartContext is empty
      this.conf = new Configuration();
    }
  }

  private void lockTheFile(String filePath) {
    fileLock.add(filePath);
  }

  private void unLockTheFile(String filePath) {
    fileLock.remove(filePath);
  }

  private boolean ifLocked(String filePath) {
    return fileLock.contains(filePath);
  }

  private long checkTheLengthOfFile(String fileName) {
    try {
      return metaStore.getFile(fileName).getLength();
    } catch (MetaStoreException e) {
      e.printStackTrace();
    }
    return 0;
  }

  private boolean isOnS3(String fileName) {
    try {
      return metaStore.getFileState(fileName)
          .getFileType().getValue() == FileState.FileType.S3.getValue();
    } catch (MetaStoreException e) {
      return false;
    }
  }

  @Override
  public List<String> getSupportedActions() {
    return actions;
  }

  @Override
  public boolean onSubmit(CmdletInfo cmdletInfo, ActionInfo actionInfo)
      throws IOException {
    // check args
    if (actionInfo.getArgs() == null) {
      throw new IOException("No arguments for the action");
    }
    String path = actionInfo.getArgs().get(HdfsAction.FILE_PATH);
    if (ifLocked(path)) {
      throw new IOException("The submit file " + path + " is locked");
    }
    if (checkTheLengthOfFile(path) == 0) {
      throw new IOException("The submit file " + path + " length is 0");
    }
    if (isOnS3(path)) {
      throw new IOException("The submit file " + path + " is already copied");
    }
    lockTheFile(path);
    LOG.debug("The file {} can be submitted", path);
    return true;
  }

  @Override
  public void onActionFinished(CmdletInfo cmdletInfo, ActionInfo actionInfo) {
    String path = actionInfo.getArgs().get(HdfsAction.FILE_PATH);
    if (actionInfo.isFinished() && actionInfo.isSuccessful()) {
      // Insert fileState
      try {
        metaStore.insertUpdateFileState(new S3FileState(path));
      } catch (MetaStoreException e) {
        LOG.error("Failed to insert file state.", e);
      }
    }
    // unlock filelock
    if (ifLocked(path)) {
      unLockTheFile(path);
      LOG.debug("unlocked copy2s3 file {}", path);
    }
  }

  @Override
  public void init() throws IOException {
  }

  @Override
  public void start() throws IOException {

  }

  @Override
  public void stop() throws IOException {
  }

}
