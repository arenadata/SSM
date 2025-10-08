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
package org.smartdata.rule.objects;


import org.smartdata.rule.parser.ValueType;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Definition of rule object 'hms'.
 */
public class HmsObject extends SmartObject {

  public static final Map<String, Property> PROPERTIES;

  static {
    PROPERTIES = new HashMap<>();
    PROPERTIES.put("name",
        new Property(
            "name",
            ValueType.STRING,
            Collections.singletonList(ValueType.STRING),
            "hive_metastore_event",
            "entity_name",
            "(entity_name LIKE SUBSTRING($0 FROM 1 FOR "
                + "NULLIF(POSITION('.' IN $0), 0) - 1)) or entity_name",
            true));
  }

  public HmsObject() {
    super(ObjectType.HMS, "hive_metastore_event");
  }

  public Map<String, Property> getProperties() {
    return PROPERTIES;
  }
}
