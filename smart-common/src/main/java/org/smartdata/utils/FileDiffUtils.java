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
package org.smartdata.utils;

import org.smartdata.model.FileDiff;

public class FileDiffUtils {
  public static final String LENGTH_ARG = "-length";
  public static final String OFFSET_ARG = "-offset";
  public static final String DEST_ARG = "-dest";

  public static String getParameter(FileDiff fileDiff, String parameter) {
    return fileDiff.getParameters().get(parameter);
  }

  public static String getOffset(FileDiff fileDiff) {
    return getParameter(fileDiff, OFFSET_ARG);
  }

  public static String getLength(FileDiff fileDiff) {
    return getParameter(fileDiff, LENGTH_ARG);
  }

  public static String getDest(FileDiff fileDiff) {
    return getParameter(fileDiff, DEST_ARG);
  }
}
