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

import com.google.gson.Gson;
import lombok.Getter;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.hdfs.protocol.HdfsFileStatus;
import org.smartdata.hdfs.action.move.AbstractMoveFileAction;
import org.smartdata.hdfs.action.move.MoverExecutor;
import org.smartdata.hdfs.action.move.MoverStatus;
import org.smartdata.model.action.FileMovePlan;

import java.io.IOException;
import java.util.Map;
import java.util.Optional;

/**
 * An action to set and enforce storage policy for a file.
 */
public class MoveFileAction extends AbstractMoveFileAction {
  private static final Gson MOVER_PLAN_DESERIALIZER = new Gson();

  private final MoverStatus status;
  private Path filePath;
  @Getter
  private String storagePolicy;
  private FileMovePlan movePlan;

  public MoveFileAction() {
    this.status = new MoverStatus();
  }

  @Override
  public void init(Map<String, String> args) {
    super.init(args);
    this.filePath = getPathArg(FILE_PATH);
    this.storagePolicy = args.get(STORAGE_POLICY);

    Optional.ofNullable(args.get(MOVE_PLAN))
        .map(plan -> MOVER_PLAN_DESERIALIZER.fromJson(plan, FileMovePlan.class))
        .ifPresent(movePlan -> {
          this.movePlan = movePlan;
          status.setTotalBlocks(movePlan.getBlockIds().size());
        });
  }

  @Override
  protected void execute() throws Exception {
    validateNonEmptyArgs(FILE_PATH, MOVE_PLAN);

    if (movePlan.isDir()) {
      localFileSystem.setStoragePolicy(filePath, storagePolicy);
      appendLog("Directory moved successfully.");
      return;
    }

    int totalReplicas = movePlan.getBlockIds().size();

    int numFailed = move();
    if (numFailed != 0) {
      String res = numFailed + " of " + totalReplicas + " replicas movement failed.";
      appendLog(res);
      throw new IOException(res);
    }

    appendLog("All scheduled " + totalReplicas + " replicas moved successfully.");
    if (movePlan.isBeingWritten() || recheckModification()) {
      appendResult("UpdateStoragePolicy=false");
      appendLog("NOTE: File may be changed during executing this action. "
          + "Will move the corresponding blocks later.");
    }
  }

  private int move() throws Exception {
    int maxMoves = movePlan.getPropertyValueInt(FileMovePlan.MAX_CONCURRENT_MOVES, 10);
    int maxRetries = movePlan.getPropertyValueInt(FileMovePlan.MAX_NUM_RETRIES, 10);
    MoverExecutor executor =
        new MoverExecutor(status, getContext().getConf(), maxRetries, maxMoves);
    return executor.executeMove(movePlan, getResultPrintStream(), getLogPrintStream());
  }

  private boolean recheckModification() {
    try {
      Optional<HdfsFileStatus> fileStatus = getHdfsFileStatus(localFileSystem, filePath);
      if (!fileStatus.isPresent()) {
        return true;
      }

      return !localFileSystem.isFileClosed(filePath)
          || (movePlan.getFileId() != 0 && fileStatus.get().getFileId() != movePlan.getFileId())
          || fileStatus.get().getLen() != movePlan.getFileLength()
          || fileStatus.get().getModificationTime() != movePlan.getModificationTime();
    } catch (Exception e) {
      return true; // check again for this case
    }
  }

  @Override
  public float getProgress() {
    return this.status.getPercentage();
  }

  @Override
  public FsType localFsType() {
    return FsType.DEFAULT_HDFS;
  }
}
