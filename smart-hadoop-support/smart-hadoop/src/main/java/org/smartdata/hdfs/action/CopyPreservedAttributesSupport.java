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
import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.smartdata.model.FileInfoDiff;
import org.smartdata.model.PreserveAttribute;

import java.io.IOException;
import java.io.PrintStream;
import java.util.EnumSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.smartdata.utils.PathUtil.getRawPath;


/**
 * Shared logic for attributes transfer support.
 */
public class CopyPreservedAttributesSupport {
  public static final String PRESERVE_ARG = "-preserve";
  /** Value of the preserve argument, which disables preserving of all the attributes. */
  public static final String PRESERVE_NONE = "none";

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

  /**
   * Returns the attributes to preserve: the default ones, if the preserve argument
   * isn't specified, or none for the {@link #PRESERVE_NONE}.
   */
  public Set<PreserveAttribute> getPreserveAttributes(Map<String, String> args) {
    return parsePreserveAttributes(args.get(PRESERVE_ARG))
        .orElse(defaultAttributes);
  }

  /**
   * Parses the comma-separated attributes of the preserve argument.
   *
   * @return parsed attributes, empty set for the {@link #PRESERVE_NONE} or empty optional,
   *     if no attributes are specified and the default attributes should be preserved
   * @throws IllegalArgumentException if the attribute is unknown or {@link #PRESERVE_NONE}
   *     is combined with other attributes
   */
  public static Optional<Set<PreserveAttribute>> parsePreserveAttributes(String rawOptions) {
    if (StringUtils.isBlank(rawOptions)) {
      return Optional.empty();
    }

    Set<PreserveAttribute> attributes = EnumSet.noneOf(PreserveAttribute.class);
    if (rawOptions.trim().equalsIgnoreCase(PRESERVE_NONE)) {
      return Optional.of(attributes);
    }

    for (String rawOption : rawOptions.split(",")) {
      String option = rawOption.trim();
      if (option.equalsIgnoreCase(PRESERVE_NONE)) {
        throw new IllegalArgumentException(
            "Preserve option '" + PRESERVE_NONE + "' can't be combined with the attributes");
      }
      if (!option.isEmpty()) {
        attributes.add(PreserveAttribute.fromOption(option));
      }
    }
    return attributes.isEmpty() ? Optional.empty() : Optional.of(attributes);
  }
}
