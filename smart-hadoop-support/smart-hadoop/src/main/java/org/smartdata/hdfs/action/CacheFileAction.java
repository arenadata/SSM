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

import org.apache.hadoop.fs.CacheFlag;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.fs.RemoteIterator;
import org.apache.hadoop.hdfs.protocol.CacheDirectiveEntry;
import org.apache.hadoop.hdfs.protocol.CacheDirectiveInfo;
import org.apache.hadoop.hdfs.protocol.HdfsFileStatus;
import org.smartdata.action.Utils;
import org.smartdata.action.annotation.ActionSignature;
import org.smartdata.hdfs.scheduler.CacheScheduler;

import java.util.EnumSet;
import java.util.Map;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * Move to Cache Action
 */
@ActionSignature(
  actionId = "cache",
  displayName = "cache",
  usage = HdfsAction.FILE_PATH + " $file " + CacheFileAction.REPLICA + " $replica "
)
public class CacheFileAction extends HdfsAction {
  public static final String REPLICA = "-replica";
  private String fileName;
  private LinkedBlockingQueue<String> actionEvents;
  private short replication = 0;

  public CacheFileAction() {
    super();
    this.actionEvents = new LinkedBlockingQueue<>();
  }

  @Override
  public void init(Map<String, String> args) {
    super.init(args);
    fileName = args.get(FILE_PATH);
    if (args.containsKey("-replica")) {
      replication = (short) Integer.parseInt(args.get(REPLICA));
    }
  }

  @Override
  protected void execute() throws Exception {
    if (fileName == null) {
      throw new IllegalArgumentException("File parameter is missing! ");
    }
    // set cache replication as the replication number of the file if not set
    if (replication == 0) {
      HdfsFileStatus fileStatus = dfsClient.getFileInfo(fileName);
      replication = fileStatus.isDir() ? 1 : fileStatus.getReplication();
    }
    addActionEvent(fileName);
    executeCacheAction(fileName);
  }

  public void addActionEvent(String fileName) throws Exception {
    actionEvents.put(fileName);
  }

  private void executeCacheAction(String fileName) throws Exception {
    if (isCached(fileName)) {
      this.appendLog("The given file has already been cached, " +
          "so there is no need to execute this action.");
      return;
    }
    this.appendLog(
        String.format(
            "Action starts at %s : cache -> %s", Utils.getFormatedCurrentTime(), fileName));
    addDirective(fileName);
  }

  public boolean isCached(String fileName) throws Exception {
    CacheDirectiveInfo.Builder filterBuilder = new CacheDirectiveInfo.Builder();
    filterBuilder.setPath(new Path(fileName));
    CacheDirectiveInfo filter = filterBuilder.build();
    RemoteIterator<CacheDirectiveEntry> directiveEntries = dfsClient.listCacheDirectives(filter);
    return directiveEntries.hasNext();
  }

  private void addDirective(String fileName) throws Exception {
    CacheDirectiveInfo.Builder filterBuilder = new CacheDirectiveInfo.Builder();
    filterBuilder.setPath(new Path(fileName))
        .setPool(CacheScheduler.SSM_POOL)
        .setReplication(replication);
    CacheDirectiveInfo filter = filterBuilder.build();
    EnumSet<CacheFlag> flags = EnumSet.noneOf(CacheFlag.class);
    dfsClient.addCacheDirective(filter, flags);
  }
}
