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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.smartdata.SmartContext;
import org.smartdata.exception.ActionRejectedException;
import org.smartdata.hdfs.action.HdfsAction;
import org.smartdata.metastore.MetaStore;
import org.smartdata.metastore.MetaStoreException;
import org.smartdata.model.ActionInfo;
import org.smartdata.model.CmdletInfo;
import org.smartdata.model.FileInfo;
import org.smartdata.model.FileState;
import org.smartdata.model.S3FileState;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;


public class Copy2S3Scheduler extends ActionSchedulerService {
  private static final Logger LOG =
      LoggerFactory.getLogger(Copy2S3Scheduler.class);
  private static final List<String> SUPPORTED_ACTIONS =
      Collections.singletonList("copy2s3");

  private final MetaStore metaStore;
  //The file in copy need to be locked
  private final Set<String> fileLock;

  public Copy2S3Scheduler(SmartContext context, MetaStore metaStore) {
    super(context, metaStore);
    this.metaStore = metaStore;
    this.fileLock = ConcurrentHashMap.newKeySet();
  }

  @Override
  public List<String> getSupportedActions() {
    return SUPPORTED_ACTIONS;
  }

  @Override
  public boolean onSubmit(CmdletInfo cmdletInfo, ActionInfo actionInfo) throws IOException {
    // check args
    String path = Optional.ofNullable(actionInfo.getArgs())
        .map(args -> args.get(HdfsAction.FILE_PATH))
        .orElseThrow(() -> new ActionRejectedException(
            "Required argument not found: " + HdfsAction.FILE_PATH));

    if (isLocked(path)) {
      throw new ActionRejectedException("The source file " + path + " is locked");
    }

    Optional<Long> fileLength = getFileLength(path);
    if (!fileLength.isPresent()) {
      throw new ActionRejectedException("The source file " + path + " not found");
    }
    if (fileLength.get() == 0) {
      throw new ActionRejectedException("The source file " + path + " length is 0");
    }
    if (isOnS3(path)) {
      throw new ActionRejectedException("The source file " + path + " is already copied");
    }
    fileLock.add(path);
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
    if (isLocked(path)) {
      fileLock.remove(path);
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


  private boolean isLocked(String filePath) {
    return fileLock.contains(filePath);
  }

  private Optional<Long> getFileLength(String fileName) {
    try {
      return Optional.ofNullable(metaStore.getFile(fileName))
          .map(FileInfo::getLength);
    } catch (MetaStoreException e) {
      LOG.warn("Error fetching info about file: {}", fileName, e);
      return Optional.empty();
    }
  }

  private boolean isOnS3(String fileName) {
    try {
      return metaStore.getFileState(fileName)
          .getFileType()
          .getValue() == FileState.FileType.S3.getValue();
    } catch (MetaStoreException e) {
      return false;
    }
  }
}
