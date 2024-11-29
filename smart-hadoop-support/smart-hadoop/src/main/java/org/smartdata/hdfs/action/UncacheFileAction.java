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

import org.apache.hadoop.fs.Path;
import org.apache.hadoop.fs.RemoteIterator;
import org.apache.hadoop.hdfs.protocol.CacheDirectiveEntry;
import org.apache.hadoop.hdfs.protocol.CacheDirectiveInfo;
import org.smartdata.action.annotation.ActionSignature;

import java.util.Map;

/**
 * An action to un-cache a file.
 */
@ActionSignature(
    actionId = "uncache",
    displayName = "uncache",
    usage = HdfsAction.FILE_PATH + " $file "
)
public class UncacheFileAction extends HdfsAction {
  private Path filePath;

  @Override
  public void init(Map<String, String> args) {
    super.init(args);
    filePath = getPathArg(FILE_PATH);
  }

  @Override
  protected void execute() throws Exception {
    validateNonEmptyArg(FILE_PATH);

    Long id = getCacheId();
    if (id == null) {
      this.appendLog(String.format("File %s is not in cache. " +
          "So there is no need to execute this action.", filePath));
      return;
    }
    localFileSystem.removeCacheDirective(id);
  }

  private Long getCacheId() throws Exception {
    CacheDirectiveInfo filter = new CacheDirectiveInfo.Builder()
        .setPath(filePath)
        .build();

    RemoteIterator<CacheDirectiveEntry> directiveEntries =
        localFileSystem.listCacheDirectives(filter);
    if (!directiveEntries.hasNext()) {
      return null;
    }
    return directiveEntries.next()
        .getInfo()
        .getId();
  }
}
