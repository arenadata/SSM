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

import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.IOUtils;
import org.smartdata.action.annotation.ActionSignature;

import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * action to Merge File
 */
@ActionSignature(
    actionId = "merge",
    displayName = "merge",
    usage = HdfsAction.FILE_PATH + "  $src " + MergeFileAction.DEST_PATH + " $dest " +
        MergeFileAction.BUF_SIZE + " $size"
)
public class MergeFileAction extends HdfsActionWithRemoteClusterSupport {
  public static final String DEST_PATH = "-dest";
  public static final String BUF_SIZE = "-bufSize";

  public static final int DEFAULT_BUF_SIZE = 64 * 1024;

  private List<Path> srcPaths;
  private Path target;
  private int bufferSize;

  @Override
  public void init(Map<String, String> args) {
    super.init(args);
    this.srcPaths = Optional.ofNullable(args.get(FILE_PATH))
        .map(paths -> paths.split(","))
        .map(Arrays::stream)
        .orElseGet(Stream::empty)
        .map(Path::new)
        .collect(Collectors.toList());

    this.target = getPathArg(DEST_PATH);
    this.bufferSize = isArgPresent(BUF_SIZE)
        ? Integer.parseInt(args.get(BUF_SIZE))
        : DEFAULT_BUF_SIZE;
  }

  @Override
  protected void preExecute() throws Exception {
    validateNonEmptyArgs(FILE_PATH, DEST_PATH);
    if (srcPaths.size() == 1) {
      throw new IllegalArgumentException("Don't accept only one source file");
    }
  }

  @Override
  protected void execute(FileSystem fileSystem) throws Exception {
    try (OutputStream destInputStream = fileSystem.create(target, true)) {
      for (Path srcPath : srcPaths) {
        try (InputStream srcInputStream = getFileSystemFor(srcPath).open(srcPath)) {
          IOUtils.copyBytes(srcInputStream,
              destInputStream, bufferSize, false);
        }
      }
    }
  }

  @Override
  protected Path getTargetFile() {
    return target;
  }
}
