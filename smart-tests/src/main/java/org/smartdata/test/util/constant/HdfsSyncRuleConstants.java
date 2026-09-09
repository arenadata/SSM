/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.smartdata.test.util.constant;

import lombok.experimental.UtilityClass;

@UtilityClass
public class HdfsSyncRuleConstants {
  public static final String SOURCE_DIR = "/data";
  public static final String SYNC_DIR = "/data/test";
  public static final String SYNC_RULE =
      "file: path matches \"/data/test/*\" | sync -dest hdfs://target-namenode.demo:8020/data/test/";
  public static final String FILE_1 = "file1";
  public static final String FILE_2 = "file2";
  public static final String FILE_1_RENAMED = "file1_renamed";
  public static final String FILE_2_RENAMED = "file2_renamed";
  public static final String FILE_1_CONTENT = "one";
  public static final String FILE_2_CONTENT = "two";
  public static final String APPENDED_PART = "two";
  public static final String APPENDED_PART_2 = "more";
  public static final String FILE_1_APPENDED_CONTENT = "onetwo";
  public static final String FILE_2_APPENDED_CONTENT = "twomore";
  public static final String DEFAULT_PERMISSIONS = "644";
  public static final String CHANGED_PERMISSIONS = "777";
}