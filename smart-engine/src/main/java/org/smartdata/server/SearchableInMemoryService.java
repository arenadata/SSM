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
package org.smartdata.server;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.mutable.MutableLong;
import org.smartdata.metastore.dao.Searchable;
import org.smartdata.metastore.model.SearchResult;
import org.smartdata.metastore.queries.PageRequest;
import org.smartdata.metastore.queries.sort.SortField;
import org.smartdata.metastore.queries.sort.Sorting;
import org.smartdata.model.TimeInterval;

import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.smartdata.utils.DateTimeUtils.intervalEndToEpoch;
import static org.smartdata.utils.DateTimeUtils.intervalStartToEpoch;

public abstract class SearchableInMemoryService<RequestT, EntityT, ColumnT extends SortField>
    implements Searchable<RequestT, EntityT, ColumnT> {

  @Override
  public SearchResult<EntityT> search(RequestT searchRequest, PageRequest<ColumnT> pageRequest) {
    MutableLong filteredEntitiesCount = new MutableLong();
    Stream<EntityT> filteredStream = filteredStream(searchRequest)
        .peek(element -> filteredEntitiesCount.increment());

    if (pageRequest != null) {
      filteredStream = Optional.ofNullable(pageRequest.getSortColumns())
          .filter(CollectionUtils::isNotEmpty)
          .flatMap(this::entityComparator)
          .map(filteredStream::sorted)
          .orElse(filteredStream);

      filteredStream = Optional.ofNullable(pageRequest.getOffset())
          .map(filteredStream::skip)
          .orElse(filteredStream);

      filteredStream = Optional.ofNullable(pageRequest.getLimit())
          .map(filteredStream::limit)
          .orElse(filteredStream);
    }

    List<EntityT> items = filteredStream.collect(Collectors.toList());
    return SearchResult.of(items, filteredEntitiesCount.longValue());
  }

  @Override
  public List<EntityT> search(RequestT searchRequest) {
    return search(searchRequest, PageRequest.empty()).getItems();
  }

  protected Predicate<Long> timeIntervalPredicate(TimeInterval timeInterval) {
    Long from = intervalStartToEpoch(timeInterval);
    Long to = intervalEndToEpoch(timeInterval);

    if (to != null && from != null) {
      return timestamp -> timestamp >= from && timestamp <= to;
    }

    if (to != null) {
      return timestamp -> timestamp <= to;
    }

    if (from != null) {
      return timestamp -> timestamp >= from;
    }

    return timestamp -> true;
  }

  protected abstract Stream<EntityT> allEntitiesStream();

  protected abstract List<Predicate<EntityT>> entityFilters(RequestT searchRequest);

  protected abstract Comparator<EntityT> sortingToComparator(Sorting<ColumnT> sorting);

  private Stream<EntityT> filteredStream(RequestT searchRequest) {
    Stream<EntityT> baseStream = allEntitiesStream();

    return Optional.ofNullable(searchRequest)
        .map(this::entityFilters)
        .flatMap(filters -> filters.stream().reduce(Predicate::and))
        .map(baseStream::filter)
        .orElse(baseStream);
  }

  private Optional<Comparator<EntityT>> entityComparator(List<Sorting<ColumnT>> sortings) {
    return sortings.stream()
        .map(this::sortingToComparator)
        .reduce(Comparator::thenComparing);
  }
}
