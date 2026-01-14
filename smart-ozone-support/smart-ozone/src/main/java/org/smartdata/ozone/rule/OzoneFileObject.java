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
package org.smartdata.ozone.rule;

import com.google.common.collect.ImmutableMap;
import org.smartdata.ozone.OzoneFileInfoDao;
import org.smartdata.rule.objects.ObjectType;
import org.smartdata.rule.objects.Property;
import org.smartdata.rule.objects.SmartObject;
import org.smartdata.rule.parser.ValueType;

import java.util.Arrays;
import java.util.Collections;
import java.util.Map;

public class OzoneFileObject extends SmartObject {

  private static final Map<String, Property> PROPERTIES =
      ImmutableMap.<String, Property>builder()
          .put("path",
              new Property("path", ValueType.STRING,
                  null, OzoneFileInfoDao.TABLE_NAME, "path"))
          .put("length",
              new Property("length", ValueType.LONG,
                  null, OzoneFileInfoDao.TABLE_NAME, "length"))
          .put("blocksize",
              new Property("blocksize", ValueType.LONG,
                  null, OzoneFileInfoDao.TABLE_NAME, "block_size"))
          .put("age",
              new Property("age", ValueType.TIMEINTVAL,
                  null, OzoneFileInfoDao.TABLE_NAME, null,
                  "($NOW - modification_time)"))
          .put("mtime",
              new Property("mtime", ValueType.TIMEPOINT,
                  null, OzoneFileInfoDao.TABLE_NAME, "modification_time"))
          .put("atime",
              new Property("atime", ValueType.TIMEPOINT,
                  null, OzoneFileInfoDao.TABLE_NAME, "access_time"))
          .put("isDir",
              new Property("isDir", ValueType.BOOLEAN,
                  null, OzoneFileInfoDao.TABLE_NAME, "is_dir"))
          .put("unsynced",
                  new Property("unsynced", ValueType.BOOLEAN,
                          null, "file_diff", null,
                          "state = 0"))
          .put("accessCount",
              new Property("accessCount", ValueType.LONG,
                  Collections.singletonList(ValueType.TIMEINTVAL),
                  "VIRTUAL_ACCESS_COUNT_TABLE", "", "count"))
          .put("ac",
              new Property("ac", ValueType.LONG,
                  Collections.singletonList(ValueType.TIMEINTVAL),
                  "VIRTUAL_ACCESS_COUNT_TABLE", "", "count"))
          .put("accessCountTop",
              new Property("accessCountTop", ValueType.LONG,
                  Arrays.asList(ValueType.TIMEINTVAL, ValueType.LONG),
                  "VIRTUAL_ACCESS_COUNT_TABLE", "", "count"))
          .put("acTop",
              new Property("acTop", ValueType.LONG,
                  Arrays.asList(ValueType.TIMEINTVAL, ValueType.LONG),
                  "VIRTUAL_ACCESS_COUNT_TABLE", "", "count"))
          .put("accessCountBottom",
              new Property("accessCountBottom", ValueType.LONG,
                  Arrays.asList(ValueType.TIMEINTVAL, ValueType.LONG),
                  "VIRTUAL_ACCESS_COUNT_TABLE", "", "count"))
          .put("acBot",
              new Property("acBot", ValueType.LONG,
                  Arrays.asList(ValueType.TIMEINTVAL, ValueType.LONG),
                  "VIRTUAL_ACCESS_COUNT_TABLE", "", "count"))
          .build();

  public OzoneFileObject() {
    super(ObjectType.FILE, PROPERTIES, OzoneFileInfoDao.TABLE_NAME);
  }
}