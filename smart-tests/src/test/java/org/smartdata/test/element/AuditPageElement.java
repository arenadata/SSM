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
package org.smartdata.test.element;

import lombok.Getter;
import org.smartdata.test.model.TableColumn;

public interface AuditPageElement {

  @Getter
  enum AuditTableColumn implements TableColumn {
    ID("ID", "id", "id"),
    USER("User", "username", "username"),
    DATE("Date", "timestamp", "timestamp"),
    OBJECT_TYPE("Object Type", "objectType", "objectType"),
    OBJECT_ID("Object ID", "objectId", "objectId"),
    OPERATION("Operation", "operation", "operation"),
    RESULT("Result", "result", "state");

    private final String name;
    private final String headerId;
    private final String cellId;

    AuditTableColumn(String name, String headerId, String cellId) {
      this.name = name;
      this.headerId = headerId;
      this.cellId = cellId;
    }

    @Override
    public int getIndex() {
      return ordinal();
    }

    @Override
    public String toString() {
      return getName();
    }
  }
}
