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
package org.smartdata.metastore.dao.impl;

import lombok.extern.slf4j.Slf4j;
import org.smartdata.metastore.MetaStoreException;
import org.smartdata.metastore.dao.AbstractDao;
import org.smartdata.metastore.dao.FileAccessPartitionDao;
import org.smartdata.metastore.model.FileAccessPartition;
import org.springframework.dao.EmptyResultDataAccessException;

import javax.sql.DataSource;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;

@Slf4j
public class DefaultFileAccessPartitionDao extends AbstractDao implements FileAccessPartitionDao {

  private static final String CREATE_NEW_PARTITION_ERR_MSG =
      "Failed to create new partition for file_access table";

  public DefaultFileAccessPartitionDao(DataSource dataSource) {
    super(dataSource, "");
  }

  @Override
  public void create(LocalDateTime date) throws MetaStoreException {
    try {
      Integer result =
          jdbcTemplate.queryForObject("select create_file_access_partition(?);", Integer.class,
              date);
      if (result == null) {
        throw new MetaStoreException(CREATE_NEW_PARTITION_ERR_MSG);
      }
      if (result == 1) {
        log.info("Created partition for file_access table for date {}", date);
      }
    } catch (Exception e) {
      throw new MetaStoreException(CREATE_NEW_PARTITION_ERR_MSG, e);
    }
  }

  @Override
  public List<FileAccessPartition> getAll() {
    String query = "SELECT inhrelid AS id, inhrelid::regclass AS name, "
        + "cast(REPLACE(REPLACE(inhrelid::regclass::text, 'file_access_', ''),'_','-') as date) "
        + "as partition_date FROM pg_catalog.pg_inherits "
        + "WHERE inhparent = 'file_access'::regclass "
        + "ORDER BY partition_date ASC;";
    try {
      return jdbcTemplate.query(query,
          (rs, rowNum) -> new FileAccessPartition(rs.getLong("id"),
              rs.getString("name"),
              rs.getDate("partition_date").toLocalDate()));
    } catch (EmptyResultDataAccessException e) {
      return Collections.emptyList();
    }
  }

  @Override
  public void remove(FileAccessPartition partition) {
    String query = String.format("DROP TABLE %s;", partition.getName());
    int result = jdbcTemplate.update(query);
    if (result == 1) {
      log.info("Dropped file access partition {}", partition);
    }
  }
}
