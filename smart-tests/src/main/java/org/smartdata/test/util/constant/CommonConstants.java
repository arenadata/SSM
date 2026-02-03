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
package org.smartdata.test.util.constant;

import lombok.experimental.UtilityClass;

import java.time.format.DateTimeFormatter;

@UtilityClass
public class CommonConstants {
  public static final String TABLE_EMPTY_VALUE = "-";
  public static final String SSM_SERVER_HOST_NAME = "ActiveSSMServer@ssm-server.demo";
  public static final String DATANODE_HOST_NAME = "SSMAgent@hadoop-datanode.demo";
  public static final String RUNNING_TIME_PATTERN = "^(?:\\d+s\\s*)?\\d+ms$";
  public static final String DATE_TIME_UI_PATTERN =
      "^(?:0[1-9]|[12][0-9]|3[01])/(?:0[1-9]|1[0-2])/\\d{4}\\s(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]$";
  public static final DateTimeFormatter DATE_TIME_FORMATTER_UI = DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm:ss");
  public static final int PAGINATION_QUANTITY = 101;
  public static final String MASTER_CONF_NAME = "smart-site-master.xml";
  public static final String AGENT_CONF_NAME = "smart-site-agent.xml";
}
