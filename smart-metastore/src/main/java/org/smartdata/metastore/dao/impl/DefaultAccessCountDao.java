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
package org.smartdata.metastore.dao.impl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.smartdata.metastore.dao.AbstractDao;
import org.smartdata.metastore.dao.AccessCountDao;
import org.smartdata.metastore.dao.AccessCountTable;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.support.rowset.SqlRowSet;

import javax.sql.DataSource;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

public class DefaultAccessCountDao extends AbstractDao implements AccessCountDao {
  static final Logger LOG = LoggerFactory.getLogger(DefaultAccessCountDao.class);

  private static final String TABLE_NAME = "access_count_table";

  public DefaultAccessCountDao(DataSource dataSource) {
    super(dataSource, TABLE_NAME);
  }

  @Override
  public void insert(AccessCountTable accessCountTable) {
    insert(accessCountTable, this::toMap);
  }

  @Override
  public void insert(AccessCountTable[] accessCountTables) {
    insert(accessCountTables, this::toMap);
  }

  @Override
  public List<AccessCountTable> getAccessCountTableByName(String name) {
    String sql = "SELECT * FROM access_count_table WHERE table_name = '" + name + "'";
    return jdbcTemplate.query(sql, new AccessCountRowMapper());
  }

  @Override
  public void delete(Long startTime, Long endTime) {
    final String sql =
        String.format(
            "DELETE FROM access_count_table WHERE start_time >= %s AND end_time <= %s",
            startTime,
            endTime);
    jdbcTemplate.update(sql);
  }

  @Override
  public void delete(AccessCountTable table) {
    final String sql = "DELETE FROM access_count_table WHERE table_name = ?";
    jdbcTemplate.update(sql, table.getTableName());
  }

  @Override
  public List<AccessCountTable> getAllSortedTables() {
    String sql = "SELECT * FROM access_count_table ORDER BY start_time ASC";
    return jdbcTemplate.query(sql, new AccessCountRowMapper());
  }

  @Override
  public void aggregateTables(
      AccessCountTable destinationTable, List<AccessCountTable> tablesToAggregate) {
    String create = AccessCountDao.createAccessCountTableSQL(destinationTable.getTableName());
    jdbcTemplate.execute(create);
    String insert =
        String.format(
            "INSERT INTO %s SELECT tmp1.%s, tmp1.%s "
                + "FROM ((SELECT %s, SUM(%s) AS %s FROM(%s) tmp0 "
                + "GROUP BY %s) AS tmp1 LEFT JOIN file ON file.fid = tmp1.fid);",
            destinationTable.getTableName(),
            DefaultAccessCountDao.FILE_FIELD,
            DefaultAccessCountDao.ACCESSCOUNT_FIELD,
            DefaultAccessCountDao.FILE_FIELD,
            DefaultAccessCountDao.ACCESSCOUNT_FIELD,
            DefaultAccessCountDao.ACCESSCOUNT_FIELD,
            getUnionStatement(tablesToAggregate),
            DefaultAccessCountDao.FILE_FIELD);
    LOG.debug("Executing access count tables aggregation: {}", insert);
    jdbcTemplate.execute(insert);
  }

  @Override
  public Map<Long, Integer> getHotFiles(List<AccessCountTable> tables, int topNum)
      throws SQLException {
    String statement =
        String.format(
            "SELECT %s, SUM(%s) AS %s FROM (%s) tmp WHERE %s IN (SELECT fid FROM file) "
                + "GROUP BY %s ORDER BY %s DESC LIMIT %s",
            DefaultAccessCountDao.FILE_FIELD,
            DefaultAccessCountDao.ACCESSCOUNT_FIELD,
            DefaultAccessCountDao.ACCESSCOUNT_FIELD,
            getUnionStatement(tables),
            DefaultAccessCountDao.FILE_FIELD,
            DefaultAccessCountDao.FILE_FIELD,
            DefaultAccessCountDao.ACCESSCOUNT_FIELD,
            topNum);
    SqlRowSet sqlRowSet = jdbcTemplate.queryForRowSet(statement);
    Map<Long, Integer> accessCounts = new HashMap<>();
    while (sqlRowSet.next()) {
      accessCounts.put(
          sqlRowSet.getLong(DefaultAccessCountDao.FILE_FIELD),
          sqlRowSet.getInt(DefaultAccessCountDao.ACCESSCOUNT_FIELD));
    }
    return accessCounts;
  }

  private String getUnionStatement(List<AccessCountTable> tables) {
    StringBuilder union = new StringBuilder();
    Iterator<AccessCountTable> tableIterator = tables.iterator();
    while (tableIterator.hasNext()) {
      AccessCountTable table = tableIterator.next();
      if (tableIterator.hasNext()) {
        union.append("SELECT * FROM " + table.getTableName() + " UNION ALL ");
      } else {
        union.append("SELECT * FROM " + table.getTableName());
      }
    }
    return union.toString();
  }

  @Override
  public void createProportionTable(AccessCountTable dest, AccessCountTable source)
      throws SQLException {
    double percentage =
        ((double) dest.getEndTime() - dest.getStartTime())
            / (source.getEndTime() - source.getStartTime());
    jdbcTemplate.execute(AccessCountDao.createAccessCountTableSQL(dest.getTableName()));
    String sql =
        String.format(
            "INSERT INTO %s SELECT %s, ROUND(%s.%s * %s) AS %s FROM %s",
            dest.getTableName(),
            DefaultAccessCountDao.FILE_FIELD,
            source.getTableName(),
            DefaultAccessCountDao.ACCESSCOUNT_FIELD,
            percentage,
            DefaultAccessCountDao.ACCESSCOUNT_FIELD,
            source.getTableName());
    jdbcTemplate.execute(sql);
  }

  @Override
  public void updateFid(long fidSrc, long fidDest) throws SQLException {
    int failedNum = 0;
    List<AccessCountTable> accessCountTables = getAllSortedTables();
    for (AccessCountTable table : accessCountTables) {
      String sql = String.format("update %s set %s=%s where %s=%s", table.getTableName(),
          DefaultAccessCountDao.FILE_FIELD, fidDest, DefaultAccessCountDao.FILE_FIELD,
          fidSrc);
      try {
        jdbcTemplate.execute(sql);
      } catch (Exception e) {
        failedNum++;
      }
    }
    // Otherwise, ignore the exception because table evictor can evict access
    // count tables, which is not synchronized. Even so, there is no impact on
    // the measurement for data temperature.
    if (failedNum == accessCountTables.size()) {
      // Throw exception if all tables are not updated.
      throw new SQLException("Failed to update fid!");
    }
  }

  private Map<String, Object> toMap(AccessCountTable accessCountTable) {
    Map<String, Object> parameters = new HashMap<>();
    parameters.put("table_name", accessCountTable.getTableName());
    parameters.put("start_time", accessCountTable.getStartTime());
    parameters.put("end_time", accessCountTable.getEndTime());
    return parameters;
  }

  private static class AccessCountRowMapper implements RowMapper<AccessCountTable> {
    @Override
    public AccessCountTable mapRow(ResultSet resultSet, int i) throws SQLException {
      return new AccessCountTable(
          resultSet.getLong("start_time"),
          resultSet.getLong("end_time"));
    }
  }
}
