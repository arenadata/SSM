/*
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
import { useMemo } from 'react';
import type { PaginationDataItem } from '@uikit/Pagination/Pagination.types';

const DECORATION_STEP = 5;

const TRAILING_ITEMS_AMOUNT = 2;

type LinksAt = 'start' | 'center' | 'end' | 'none';

export interface UsePaginationParams {
  /**
   * Current page. Starts with 0
   * */
  pageNumber: number;
  /**
   * Total pages
   * */
  totalItems: number;
  /**
   * Amount of items per page
   * */
  perPage: number;
  /**
   * Max amount of links to show
   * E.g., if `maxItems` === 7
   * 0 1 2 3 4 … 9
   * 0 … 4 5 6 … 9
   * 0 … 5 6 7 8 9
   * */
  maxItems: number;
  /**
   * external flag for override internal hasNext
   */
  isNextBtn?: false | true | null;
}

interface Results {
  hasNext: boolean;
  hasPrev: boolean;
  pageItems: PaginationDataItem[];
  totalPages: number;
}

export function usePagination(params: UsePaginationParams): Results {
  const { pageNumber, totalItems, perPage, maxItems, isNextBtn } = params;

  const totalPages = Math.max(1, Math.ceil(totalItems / perPage));
  const hasNext = typeof isNextBtn === 'boolean' ? isNextBtn : pageNumber < totalPages - 1;
  const hasPrev = pageNumber > 0;

  const linksAt = useMemo<LinksAt>(() => {
    // All pages fits, no need for dots
    // 1 2 3 4 5 6 7
    if (totalPages <= maxItems) {
      return 'none';
    }

    const boundary = maxItems - TRAILING_ITEMS_AMOUNT - 1;

    // 1 2 3 4 5 … 100
    //       ^
    if (pageNumber <= boundary) {
      return 'start';
    }

    // 1 … 96 97 98 99 100
    //          ^
    if (pageNumber >= totalPages - 1 - boundary) {
      return 'end';
    }

    // 1 … 48 49 50 51 52 … 100
    //          ^
    return 'center';
  }, [pageNumber, totalPages, maxItems]);

  // Dots lead on these pages (±5 from current)
  const prevDecorationPage = Math.max(0, pageNumber - DECORATION_STEP);
  const nextDecorationPage = Math.min(totalPages - 1, pageNumber + DECORATION_STEP);

  const pageItems = useMemo<PaginationDataItem[]>(() => {
    const items: PaginationDataItem[] = [];

    const addPage = (num: number) => {
      items.push({
        key: `page-${num}`,
        type: 'page',
        label: (num + 1).toString(),
        pageNumber: num,
      });
    };

    const addDots = (targetPage: number) => {
      items.push({
        key: `dots-${items.length}`,
        type: 'decoration',
        label: '...',
        pageNumber: targetPage,
      });
    };

    switch (linksAt) {
      case 'none': {
        for (let i = 0; i < totalPages; i++) {
          addPage(i);
        }
        break;
      }

      case 'start': {
        for (let i = 0; i < maxItems - 1; i++) {
          addPage(i);
        }
        addDots(nextDecorationPage);
        addPage(totalPages - 1);
        break;
      }

      case 'center': {
        addPage(0);
        addDots(prevDecorationPage);

        const middleCount = maxItems - 4;
        const half = Math.floor(middleCount / 2);
        let start = pageNumber - half;
        let end = pageNumber + half + (middleCount % 2);

        if (start < 2) {
          end += 2 - start;
          start = 2;
        }
        if (end > totalPages - 3) {
          start -= end - (totalPages - 3);
          end = totalPages - 3;
        }
        start = Math.max(start, 2);
        end = Math.min(end, totalPages - 3);

        for (let i = start; i <= end; i++) {
          addPage(i);
        }

        addDots(nextDecorationPage);
        addPage(totalPages - 1);
        break;
      }

      case 'end': {
        addPage(0);
        addDots(prevDecorationPage);

        for (let i = totalPages - (maxItems - 1); i < totalPages; i++) {
          addPage(i);
        }
        break;
      }
    }

    return items;
  }, [linksAt, pageNumber, totalPages, maxItems, prevDecorationPage, nextDecorationPage]);

  return {
    hasNext,
    hasPrev,
    pageItems,
    totalPages,
  };
}
