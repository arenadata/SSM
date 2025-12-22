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

import org.smartdata.action.AbstractActionFactory;
import org.smartdata.action.SmartAction;

import java.util.Arrays;
import java.util.List;

/**
 * Built-in smart actions for HDFS system.
 */
public class HdfsActionFactory extends AbstractActionFactory {

  @Override
  protected List<Class<? extends SmartAction>> supportedActionClasses() {
    return Arrays.asList(
        AllSsdFileAction.class,
        AllDiskFileAction.class,
        OneSsdFileAction.class,
        OneDiskFileAction.class,
        RamDiskFileAction.class,
        ArchiveFileAction.class,
        CacheFileAction.class,
        UncacheFileAction.class,
        ReadFileAction.class,
        WriteFileAction.class,
        CheckStorageAction.class,
        SetXAttrAction.class,
        CopyFileAction.class,
        CopyDirectoryAction.class,
        DeleteFileAction.class,
        RenameFileAction.class,
        ListFileAction.class,
        ConcatFileAction.class,
        AppendFileAction.class,
        MergeFileAction.class,
        MetaDataAction.class,
        Copy2S3Action.class,
        CompressionAction.class,
        DecompressionAction.class,
        CheckCompressAction.class,
        TruncateAction.class,
        SmallFileCompactAction.class,
        SmallFileUncompactAction.class,
        CheckSumAction.class,
        DistCpAction.class,
        ListErasureCodingPolicy.class,
        CheckErasureCodingPolicy.class,
        ErasureCodingAction.class,
        UnErasureCodingAction.class,
        AddErasureCodingPolicy.class,
        RemoveErasureCodingPolicy.class,
        EnableErasureCodingPolicy.class,
        DisableErasureCodingPolicy.class
    );
  }
}
