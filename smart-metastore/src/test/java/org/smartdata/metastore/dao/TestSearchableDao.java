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
package org.smartdata.metastore.dao;

import org.junit.Assert;
import org.smartdata.metastore.TestDaoBase;
import org.smartdata.metastore.model.SearchResult;
import org.smartdata.metastore.queries.PageRequest;
import org.smartdata.metastore.queries.sort.SortField;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.Assert.assertEquals;

public abstract class TestSearchableDao<
    RequestT, EntityT, ColumnT extends SortField, IdT> extends TestDaoBase {
  // used to fail if query returns more results then expected
  private static final int ADDITIONAL_LIMIT = 5;

  protected abstract Searchable<RequestT, EntityT, ColumnT> searchable();

  protected abstract IdT getIdentifier(EntityT entityT);

  protected abstract ColumnT defaultSortField();

  @SafeVarargs
  protected final void testSearch(RequestT searchRequest, IdT... expectedIds) {
    PageRequest<ColumnT> singleEntityRequest = pageRequest(0L, 1);

    List<IdT> expectedIdsList = expectedIds.length == 0
        ? Collections.emptyList()
        : Collections.singletonList(expectedIds[0]);

    // check pagination: at first limit results with 1 row
    testPagedSearch(searchRequest, singleEntityRequest,
        expectedIds.length, expectedIdsList);

    if (expectedIds.length > 1) {
      PageRequest<ColumnT> remainingResultsRequest = pageRequest(1L,
          expectedIds.length - 1 + ADDITIONAL_LIMIT);

      expectedIdsList = Arrays.asList(expectedIds).subList(1, expectedIds.length);

      // fetch remaining rows
      testPagedSearch(searchRequest, remainingResultsRequest,
          expectedIds.length, expectedIdsList);
    }
  }

  @SafeVarargs
  protected final void testPagedSearch(
      RequestT searchRequest,
      PageRequest<ColumnT> pageRequest,
      IdT... expectedIds) {
    testPagedSearch(
        searchRequest,
        pageRequest,
        expectedIds.length,
        Arrays.asList(expectedIds));
  }

  private void testPagedSearch(
      RequestT searchRequest,
      PageRequest<ColumnT> pageRequest,
      long expectedTotal,
      List<IdT> expectedIds) {
    SearchResult<EntityT> searchResult = null;
    try {
      searchResult = searchable().search(searchRequest, pageRequest);
    } catch (Exception e) {
      Assert.fail(e.getMessage());
    }

    List<EntityT> items = searchResult.getItems();
    assertEquals(expectedTotal, searchResult.getTotal());
    assertEquals(expectedIds.size(), items.size());

    List<IdT> actualEventTimestamps = items.stream()
        .map(this::getIdentifier)
        .collect(Collectors.toList());

    assertEquals(expectedIds, actualEventTimestamps);
  }

  private PageRequest<ColumnT> pageRequest(long offset, int limit) {
    return PageRequest.<ColumnT>builder()
        .offset(offset)
        .limit(limit)
        .sortByAsc(defaultSortField())
        .build();
  }
}
