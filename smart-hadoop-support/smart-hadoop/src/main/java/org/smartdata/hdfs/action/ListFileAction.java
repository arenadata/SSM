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

import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.fs.RemoteIterator;
import org.smartdata.action.Utils;
import org.smartdata.action.annotation.ActionSignature;

import java.io.IOException;
import java.text.DecimalFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Queue;

/**
 * An action to list files in a directory.
 */
@ActionSignature(
    actionId = "list",
    displayName = "list",
    usage = HdfsAction.FILE_PATH + " $src1"
        + ListFileAction.RECURSIVELY
        + ListFileAction.PRETTY_SIZES
)
public class ListFileAction extends HdfsAction {
  // Options
  public static final String RECURSIVELY = "-r";
  public static final String PRETTY_SIZES = "-h";

  public static final SimpleDateFormat FILE_DATE_FORMAT =
      new SimpleDateFormat("yyyy-MM-dd HH:mm");
  public static final DecimalFormat FILE_SIZE_FORMAT =
      new DecimalFormat("#,##0.#");
  public static final List<String> SIZE_UNITS = Arrays.asList(
      "", "K", "M", "G", "T"
  );

  private String srcPath;
  private boolean recursively = false;
  private boolean human = false;

  @Override
  public void init(Map<String, String> args) {
    super.init(args);
    this.srcPath = args.get(FILE_PATH);
    if (args.containsKey(RECURSIVELY)) {
      this.recursively = true;
    }
    if (args.containsKey(PRETTY_SIZES)) {
      this.human = true;
    }
  }

  @Override
  protected void execute() throws Exception {
    Path listingRoot = Optional.ofNullable(srcPath)
        .filter(StringUtils::isNotBlank)
        .map(Path::new)
        .orElseThrow(() -> new IllegalArgumentException("File parameter is missing."));

    appendLog(
        String.format("Action starts at %s : List %s", Utils.getFormatedCurrentTime(), srcPath));

    if (srcPath.startsWith("hdfs")) {
      listDirectory(listingRoot.getFileSystem(new Configuration()), listingRoot);
    } else {
      withDefaultFs();
      listDirectory(listingRoot.getFileSystem(getContext().getConf()), listingRoot);
    }
  }

  private void listDirectory(FileSystem fs, Path root) throws IOException {
    FileStatus rootStatus = fs.getFileStatus(root);
    if (rootStatus == null) {
      appendResult("File not found!");
      return;
    }

    if (!rootStatus.isDirectory()) {
      appendResult(formatFileStatus(rootStatus));
      return;
    }

    Queue<FileStatus> fileQueue = new ArrayDeque<>();
    addFilesFromDir(fs, root, fileQueue);

    while (!fileQueue.isEmpty()) {
      FileStatus fileStatus = fileQueue.poll();
      appendResult(String.format("%s", formatFileStatus(fileStatus)));

      if (recursively && fileStatus.isDirectory()) {
        addFilesFromDir(fs, fileStatus.getPath(), fileQueue);
      }
    }
  }

  private void addFilesFromDir(FileSystem fs, Path root, Queue<FileStatus> container) throws IOException {
    RemoteIterator<FileStatus> pathIterator = fs.listStatusIterator(root);
    while (pathIterator.hasNext()) {
      container.add(pathIterator.next());
    }
  }

  private String formatFileStatus(FileStatus status) {
    return String.format("%s%s %5d %s\t%s\t%13s %s %s",
        status.isDirectory() ? 'd' : '-',
        status.getPermission(),
        status.getReplication(),
        status.getOwner(),
        status.getGroup(),
        human ? readableFileSize(status.getLen()) : status.getLen(),
        FILE_DATE_FORMAT.format(status.getModificationTime()), status.getPath());
  }

  private String readableFileSize(long size) {
    if (size <= 0) {
      return "0";
    }
    int digitGroups = (int) (Math.log10(size) / Math.log10(1024));
    return digitGroups == 0
        ? Long.toString(size)
        : FILE_SIZE_FORMAT.format(size / Math.pow(1024, digitGroups))
        + " " + SIZE_UNITS.get(digitGroups);
  }

}
