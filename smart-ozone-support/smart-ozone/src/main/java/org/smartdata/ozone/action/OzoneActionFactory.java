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
package org.smartdata.ozone.action;

import org.smartdata.action.AbstractActionFactory;
import org.smartdata.action.SmartAction;
import org.smartdata.action.SyncAction;
import org.smartdata.hdfs.action.Copy2S3Action;
import org.smartdata.hdfs.action.CopyDirectoryAction;
import org.smartdata.hdfs.action.CopyFileAction;
import org.smartdata.hdfs.action.DeleteFileAction;
import org.smartdata.hdfs.action.DistCpAction;
import org.smartdata.hdfs.action.ListFileAction;
import org.smartdata.hdfs.action.MetaDataAction;
import org.smartdata.hdfs.action.ReadFileAction;
import org.smartdata.hdfs.action.RenameFileAction;
import org.smartdata.hdfs.action.WriteFileAction;

import java.util.Arrays;
import java.util.List;

public class OzoneActionFactory extends AbstractActionFactory {

  @Override
  protected List<Class<? extends SmartAction>> supportedActionClasses() {
    return Arrays.asList(
        CopyFileAction.class,
        Copy2S3Action.class,
        DeleteFileAction.class,
        RenameFileAction.class,
        ListFileAction.class,
        ReadFileAction.class,
        WriteFileAction.class,
        SyncAction.class,
        DistCpAction.class,
        CopyDirectoryAction.class,
        MetaDataAction.class
    );
  }
}
