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
import java.io.IOException;
import java.net.URI;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.apache.commons.lang.StringUtils;
import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.smartdata.model.FileInfoDiff;


/**
 * Base class for all actions with file attributes transfer support.
 */
public abstract class CopyPreservedAttributesAction extends HdfsAction {
  public static final String PRESERVE = "-preserve";

  private final Set<PreserveAttribute> supportedAttributes;
  private final Set<PreserveAttribute> defaultAttributes;

  private List<String> rawPreserveAttributes = Collections.emptyList();

  private UpdateFileMetadataSupport updateMetadataSupport;

  public CopyPreservedAttributesAction(Set<PreserveAttribute> defaultAttributes) {
    this(Sets.newHashSet(PreserveAttribute.values()), defaultAttributes);
  }

  public CopyPreservedAttributesAction(Set<PreserveAttribute> supportedAttributes,
                                       Set<PreserveAttribute> defaultAttributes) {
    this.supportedAttributes = supportedAttributes;
    this.defaultAttributes = defaultAttributes;
  }

  @Override
  public void init(Map<String, String> args) {
    super.init(args);
    if (StringUtils.isNotBlank(args.get(PRESERVE))) {
      rawPreserveAttributes = Arrays.asList(args.get(PRESERVE).split(","));
    }
    updateMetadataSupport = new UpdateFileMetadataSupport(
        getContext().getConf(), getLogPrintStream());
  }

  protected Set<PreserveAttribute> parsePreserveAttributes() {
    Set<PreserveAttribute> attributesFromOptions = rawPreserveAttributes
        .stream()
        .map(PreserveAttribute::fromOption)
        .collect(Collectors.toSet());

    return attributesFromOptions.isEmpty()
        ? defaultAttributes
        : attributesFromOptions;
  }

  protected void copyFileAttributes(String srcPath, String destPath,
                                    Set<PreserveAttribute> preserveAttributes) throws IOException {
    if (preserveAttributes.isEmpty()) {
      return;
    }

    appendLog(
        String.format("Copy attributes from %s to %s", srcPath, destPath));

    FileStatus srcFileStatus = getFileStatus(srcPath);
    FileInfoDiff fileInfoDiff = new FileInfoDiff().setPath(destPath);

    supportedAttributes
        .stream()
        .filter(preserveAttributes::contains)
        .forEach(attribute -> attribute.applyToDiff(fileInfoDiff, srcFileStatus));

    updateMetadataSupport.changeFileMetadata(fileInfoDiff);
    appendLog("Successfully transferred file attributes: " + preserveAttributes);
  }

  protected FileStatus getFileStatus(String fileName) throws IOException {
    if (fileName.startsWith("hdfs")) {
      FileSystem fs = FileSystem.get(URI.create(fileName), getContext().getConf());
      // Get InputStream from URL
      return fs.getFileStatus(new Path(fileName));
    }
    return (FileStatus) dfsClient.getFileInfo(fileName);
  }

  public enum PreserveAttribute {
    OWNER("owner") {
      @Override
      public void applyToDiff(FileInfoDiff fileInfoDiff, FileStatus srcFileStatus) {
        fileInfoDiff.setOwner(srcFileStatus.getOwner());
      }
    },
    GROUP("group") {
      @Override
      public void applyToDiff(FileInfoDiff fileInfoDiff, FileStatus srcFileStatus) {
        fileInfoDiff.setGroup(srcFileStatus.getGroup());
      }
    },
    PERMISSIONS("permissions") {
      @Override
      public void applyToDiff(FileInfoDiff fileInfoDiff, FileStatus srcFileStatus) {
        fileInfoDiff.setPermission(srcFileStatus.getPermission().toShort());
      }
    },
    REPLICATION_NUMBER("replication") {
      @Override
      public void applyToDiff(FileInfoDiff fileInfoDiff, FileStatus srcFileStatus) {
        fileInfoDiff.setBlockReplication(srcFileStatus.getReplication());
      }
    },
    MODIFICATION_TIME("modification-time") {
      @Override
      public void applyToDiff(FileInfoDiff fileInfoDiff, FileStatus srcFileStatus) {
        fileInfoDiff.setModificationTime(srcFileStatus.getModificationTime());
      }
    };

    private final String name;

    PreserveAttribute(String name) {
      this.name = name;
    }

    public abstract void applyToDiff(FileInfoDiff fileInfoDiff, FileStatus srcFileStatus);

    @Override
    public String toString() {
      return name;
    }

    protected static PreserveAttribute fromOption(String option) {
      return Arrays.stream(PreserveAttribute.values())
          .filter(attr -> attr.toString().equals(option))
          .findFirst()
          .orElseThrow(() ->
              new IllegalArgumentException("Wrong preserve attribute: " + option));
    }
  }
}
