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
package org.smartdata.ozone.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import org.smartdata.model.BaseFileInfo;

@Data
@AllArgsConstructor
@Builder(toBuilder = true)
public class OzoneFileInfo implements FsObjectStreamRecord, BaseFileInfo {
  private String path;
  private long fileId;
  private long length;
  private short blockReplication;
  private long blockSize;
  private long modificationTime;
  private long accessTime;
  private boolean isVolume;
  private boolean isBucket;
  private boolean isS3;
  private boolean isDir;
  private String owner;
  private String group;
  private short permission;
  private String erasureCodingPolicy;
}