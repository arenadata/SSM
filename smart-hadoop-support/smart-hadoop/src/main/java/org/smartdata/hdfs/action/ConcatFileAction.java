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

import org.apache.hadoop.fs.Options;
import org.apache.hadoop.fs.Path;
import org.smartdata.action.annotation.ActionSignature;

import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Deque;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * An action to merge a list of file,
 * the source file is separated by comma,
 * and the target file will be over writen
 */
@ActionSignature(
    actionId = "concat",
    displayName = "concat",
    usage = HdfsAction.FILE_PATH + " $src " + ConcatFileAction.DEST_PATH + " $dest"
)
public class ConcatFileAction extends HdfsAction {
  public static final String DEST_PATH = "-dest";

  private Deque<Path> srcPaths;
  private Path targetPath;

  @Override
  public void init(Map<String, String> args) {
    super.init(args);
    this.srcPaths = Optional.ofNullable(args.get(FILE_PATH))
        .map(paths -> paths.split(","))
        .map(Arrays::stream)
        .orElseGet(Stream::empty)
        .map(Path::new)
        .collect(Collectors.toCollection(ArrayDeque::new));
    this.targetPath = getPathArg(DEST_PATH);
  }

  @Override
  protected void execute() throws Exception {
    validateNonEmptyArgs(FILE_PATH, DEST_PATH);
    if (srcPaths.isEmpty()) {
      throw new IllegalArgumentException("Source files not provided");
    }
    if (srcPaths.size() == 1) {
      throw new IllegalArgumentException("Don't accept only one source file");
    }

    for (Path sourcePath : srcPaths) {
      if (localFileSystem.getFileStatus(sourcePath).isDirectory()) {
        throw new IllegalArgumentException("File parameter is not file");
      }
    }

    Path firstPath = srcPaths.removeFirst();
    Path[] restPaths = srcPaths.toArray(new Path[0]);
    localFileSystem.concat(firstPath, restPaths);
    localFileSystem.rename(firstPath, targetPath, Options.Rename.OVERWRITE);
  }
}
