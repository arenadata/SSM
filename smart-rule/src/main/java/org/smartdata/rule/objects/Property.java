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

import lombok.Data;
import org.smartdata.rule.parser.ValueType;

import java.util.List;

/**
 * Property of SSM object.
 */
@Data
public class Property {
  private final String propertyName;
  private final ValueType valueType;
  private final List<ValueType> paramsTypes;

  private final String tableName;
  private final String tableColumn;
  private final String formatTemplate;
  private final boolean acceptsImplicitParameters;

  public Property(
      String propertyName,
      ValueType retType,
      List<ValueType> paramsTypes,
      String tableName,
      String tableColumn) {
    this(propertyName, retType, paramsTypes, tableName, tableColumn, null, false);
  }

  // TODO: re-arch to couple paramsTypes and formatTemplate
  public Property(
      String propertyName,
      ValueType retType,
      List<ValueType> paramsTypes,
      String tableName,
      String tableColumn,
      String formatTemplate) {
    this(propertyName, retType, paramsTypes, tableName, tableColumn, formatTemplate, false);
  }

  public Property(
      String propertyName,
      ValueType retType,
      List<ValueType> paramsTypes,
      String tableName,
      String tableColumn,
      String formatTemplate,
      boolean acceptsImplicitParameters) {
    this.propertyName = propertyName;
    this.valueType = retType;
    this.paramsTypes = paramsTypes;
    this.tableName = tableName;
    this.tableColumn = tableColumn;
    this.formatTemplate = formatTemplate;
    this.acceptsImplicitParameters = acceptsImplicitParameters;
  }

  public String formatParameters(List<Object> values) {
    if (formatTemplate == null) {
      return tableColumn;
    }

    if (values == null) {
      return formatTemplate;
    }

    String ret = formatTemplate;

    // TODO: need more checks to ensure replace correctly
    for (int i = 0; i < values.size(); i++) {
      if (ret.contains("$" + i)) {
        String v;
        switch (paramsTypes.get(i)) {
          case TIMEINTVAL:
          case LONG:
            v = values.get(i).toString();
            break;
          case STRING:
            v = "'" + values.get(i) + "'";
            break;
          default:
            v = null;  // TODO: throw exception
        }
        if (v != null) {
          ret = ret.replaceAll("\\$" + i, v);
        }
      }
    }
    return ret;
  }
}
