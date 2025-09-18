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

import com.codeborne.selenide.SelenideElement;
import lombok.Getter;
import org.smartdata.test.model.TableColumn;

import static com.codeborne.selenide.Selenide.$x;

public interface FilesInCachePageElement {

  SelenideElement FILES_IN_CACHE_TOOLBAR = $x("//*[contains(@class, 'cachedFilesToolbar')]");

  @Getter
  enum ClusterInfoFilesInCacheTableColumn implements TableColumn {
    ID("ID", "id"),
    FILE_PATH("File path", "path"),
    CACHED_TIME("Cached Time", "cachedTime"),
    LAST_ACCESSED_TIME("Last Accessed Time", "lastAccessTime"),
    ACCESS_COUNT("Access count", "accessCount");

    private final String name;
    private final String headerId;

    ClusterInfoFilesInCacheTableColumn(String name, String headerId) {
      this.name = name;
      this.headerId = headerId;
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
