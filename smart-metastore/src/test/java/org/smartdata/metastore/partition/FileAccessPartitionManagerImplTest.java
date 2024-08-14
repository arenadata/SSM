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
package org.smartdata.metastore.partition;

import org.junit.Before;
import org.junit.Test;
import org.smartdata.metastore.TestDaoBase;
import org.smartdata.metastore.model.FileAccessPartition;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.Assert.assertEquals;

public class FileAccessPartitionManagerImplTest extends TestDaoBase {
  private static final String FILE_ACCESS_PARTITION_NAME_TEMPLATE = "file_access_%s";
  private FileAccessPartitionManager fileAccessPartitionManager;
  private static final DateTimeFormatter PARTITION_DATE_TIME_FORMAT =
      DateTimeFormatter.ofPattern("yyyy_MM_dd");

  @Before
  public void setUp() throws Exception {
    fileAccessPartitionManager = new FileAccessPartitionManagerImpl(metaStore);
  }

  @Test
  public void testCreatePartitions() {
    LocalDate currentDate = LocalDate.now().withDayOfMonth(1);
    String currentMonthPartition =
        String.format(FILE_ACCESS_PARTITION_NAME_TEMPLATE,
            currentDate.format(PARTITION_DATE_TIME_FORMAT));
    String nextMonthPartition = String.format(FILE_ACCESS_PARTITION_NAME_TEMPLATE,
        currentDate.plusMonths(1).withDayOfMonth(1).format(PARTITION_DATE_TIME_FORMAT));
    fileAccessPartitionManager.createNewPartitions();
    List<FileAccessPartition> partitions = metaStore.fileAccessPartitionDao().getAll();
    assertEquals(Arrays.asList(currentMonthPartition, nextMonthPartition), partitions.stream().map(
        FileAccessPartition::getName).collect(Collectors.toList()));
  }
}
