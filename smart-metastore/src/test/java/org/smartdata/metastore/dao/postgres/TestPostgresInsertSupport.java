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
package org.smartdata.metastore.dao.postgres;

import org.junit.Test;

import javax.sql.DataSource;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;

public class TestPostgresInsertSupport {

  @Test
  public void generateUpsertSqlTemplate() {
    DataSource dataSource = mock(DataSource.class);
    PostgresInsertSupport upsertSupport = new PostgresInsertSupport(dataSource, "");

    Map<String, Object> namedParameters = new HashMap<>();
    namedParameters.put("primaryKey", "key");
    namedParameters.put("intField", 1);
    namedParameters.put("strField", "str");
    namedParameters.put("floatField", 1.0f);
    namedParameters.put("jsonField", "{\"key\": \"value\")");

    String sqlTemplate = upsertSupport.generateSqlTemplate(namedParameters, "primaryKey", true);

    String expectedSqlTemplate =
        "INSERT INTO (floatField, jsonField, strField, intField, primaryKey)\n"
            + "VALUES (:floatField,\n"
            + ":jsonField,\n"
            + ":strField,\n"
            + ":intField,\n"
            + ":primaryKey)\n"
            + "ON CONFLICT (primaryKey)\n"
            + "DO UPDATE SET floatField = :floatField,\n"
            + "jsonField = :jsonField,\n"
            + "strField = :strField,\n"
            + "intField = :intField,\n"
            + "primaryKey = :primaryKey";

    assertEquals(expectedSqlTemplate, sqlTemplate);
  }

  @Test
  public void generateInsertIfNotPresentSqlTemplate() {
    DataSource dataSource = mock(DataSource.class);
    PostgresInsertSupport upsertSupport = new PostgresInsertSupport(dataSource, "");

    Map<String, Object> namedParameters = new HashMap<>();
    namedParameters.put("primaryKey", "key");
    namedParameters.put("intField", 1);
    namedParameters.put("strField", "str");
    namedParameters.put("floatField", 1.0f);
    namedParameters.put("jsonField", "{\"key\": \"value\")");

    String sqlTemplate = upsertSupport.generateSqlTemplate(
        namedParameters, "primaryKey", false);

    String expectedSqlTemplate =
        "INSERT INTO (floatField, jsonField, strField, intField, primaryKey)\n"
            + "VALUES (:floatField,\n"
            + ":jsonField,\n"
            + ":strField,\n"
            + ":intField,\n"
            + ":primaryKey)\n"
            + "ON CONFLICT (primaryKey)\n"
            + "DO NOTHING";

    assertEquals(expectedSqlTemplate, sqlTemplate);
  }
}
