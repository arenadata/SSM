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

import com.google.common.collect.Sets;
import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.smartdata.model.FileInfoDiff;

import java.io.IOException;
import java.io.PrintStream;
import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static org.smartdata.utils.PathUtil.getRawPath;


/**
 * Shared logic for attributes transfer support.
 */
public class CopyPreservedAttributesSupport {
  public static final String PRESERVE_ARG = "-preserve";

  private final Set<PreserveAttribute> supportedAttributes;
  private final Set<PreserveAttribute> defaultAttributes;
  private final UpdateFileMetadataSupport updateMetadataSupport;
  private final PrintStream logOutput;

  public CopyPreservedAttributesSupport(
      Set<PreserveAttribute> defaultAttributes,
      PrintStream logOutput) {
    this(Sets.newHashSet(PreserveAttribute.values()), defaultAttributes, logOutput);
  }

  public CopyPreservedAttributesSupport(Set<PreserveAttribute> supportedAttributes,
      Set<PreserveAttribute> defaultAttributes,
      PrintStream logOutput) {
    this.supportedAttributes = supportedAttributes;
    this.defaultAttributes = defaultAttributes;
    this.logOutput = logOutput;
    this.updateMetadataSupport = new UpdateFileMetadataSupport(logOutput);
  }

  public void execute(
      FileStatus srcFileStatus,
      Path destPath,
      FileSystem destFileSystem,
      Map<String, String> actionArgs) throws IOException {
    execute(srcFileStatus, destPath, destFileSystem, getPreserveAttributes(actionArgs));
  }

  public void execute(
      FileStatus srcFileStatus,
      Path destPath,
      FileSystem destFileSystem,
      Set<PreserveAttribute> preserveAttributes) throws IOException {
    logOutput.printf("Copy attributes from %s to %s%n", srcFileStatus.getPath(), destPath);

    FileInfoDiff fileInfoDiff = new FileInfoDiff().setPath(getRawPath(destPath));
    supportedAttributes
        .stream()
        .filter(preserveAttributes::contains)
        .forEach(attribute -> attribute.applyToDiff(fileInfoDiff, srcFileStatus));

    execute(fileInfoDiff, destFileSystem, preserveAttributes);
  }

  public void execute(
      FileInfoDiff fileInfoDiff,
      FileSystem destFileSystem,
      Set<PreserveAttribute> preserveAttributes) throws IOException {
    supportedAttributes
        .stream()
        .filter(attr -> !preserveAttributes.contains(attr))
        .forEach(attribute -> attribute.applyToDiff(fileInfoDiff, null));

    updateMetadataSupport.changeFileMetadata(destFileSystem, fileInfoDiff);
    logOutput.println("Successfully transferred file attributes: " + preserveAttributes);
  }

  public Set<PreserveAttribute> getPreserveAttributes(Map<String, String> args) {
    Set<PreserveAttribute> preserveAttributes = Optional.ofNullable(args.get(PRESERVE_ARG))
        .map(rawArg -> rawArg.split(","))
        .stream()
        .flatMap(Arrays::stream)
        .map(String::trim)
        .filter(rawAttribute -> !rawAttribute.isEmpty())
        .map(PreserveAttribute::fromOption)
        .collect(Collectors.toSet());
    return preserveAttributes.isEmpty()
        ? defaultAttributes
        : preserveAttributes;
  }
}
