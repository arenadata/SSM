/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.smartdata.hdfs.metric.fetcher;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.apache.hadoop.hdfs.inotify.Event;
import org.junit.Assert;
import org.junit.Test;
import org.smartdata.model.PathChecker;

public class TestInotifyEventFilter {

  private static final String IGNORE_PATTERN = ".*ignored.*";

  private final INotifyEventFilter eventFilter = new INotifyEventFilter(
      new PathChecker(
          Collections.singletonList(IGNORE_PATTERN),
          Collections.singletonList("/")
      )
  );

  @Test
  public void testFilterEvents() {
    List<Event> allEvents = new ArrayList<>();
    List<Event> expectedFilteredEvents = new ArrayList<>();

    Event.CreateEvent createEvent = new Event.CreateEvent.Builder()
        .path("/normal/path.txt")
        .build();
    Event.CreateEvent ignoredCreateEvent = new Event.CreateEvent.Builder()
        .path("/ignored/path.txt")
        .build();
    Collections.addAll(allEvents, createEvent, ignoredCreateEvent);
    expectedFilteredEvents.add(createEvent);

    Event.CloseEvent closeEvent = new Event.CloseEvent("/normal/path.txt", 1, 1);
    Event.CloseEvent ignoredCloseEvent = new Event.CloseEvent("/dir/ignored.txt", 1, 1);
    Collections.addAll(allEvents, closeEvent, ignoredCloseEvent);
    expectedFilteredEvents.add(closeEvent);

    Event.RenameEvent ignoredDstRenameEvent = new Event.RenameEvent.Builder()
        .srcPath("/src/path")
        .dstPath("/ignored/path")
        .build();
    Event.RenameEvent ignoredSrcRenameEvent = new Event.RenameEvent.Builder()
        .srcPath("/ignored/path")
        .dstPath("/dst/path")
        .build();
    Event.RenameEvent ignoredRenameEvent = new Event.RenameEvent.Builder()
        .srcPath("/src/ignored/path")
        .dstPath("/dst/ignored/path")
        .build();
    Collections.addAll(allEvents, ignoredDstRenameEvent, ignoredSrcRenameEvent, ignoredRenameEvent);
    Collections.addAll(expectedFilteredEvents, ignoredDstRenameEvent, ignoredSrcRenameEvent);

    Event.MetadataUpdateEvent metadataUpdateEvent = new Event.MetadataUpdateEvent.Builder()
        .path("/tmp/anotherDir/test_file")
        .build();
    Event.MetadataUpdateEvent ignoredMetadataUpdateEvent = new Event.MetadataUpdateEvent.Builder()
        .path("/.ignored")
        .build();
    Collections.addAll(allEvents, metadataUpdateEvent, ignoredMetadataUpdateEvent);
    expectedFilteredEvents.add(metadataUpdateEvent);

    Event.AppendEvent appendEvent = new Event.AppendEvent.Builder()
        .path("/normal.file")
        .build();
    Event.AppendEvent ignoredAppendEvent = new Event.AppendEvent.Builder()
        .path("/src/tmp/ignoredfile")
        .build();
    Collections.addAll(allEvents, appendEvent, ignoredAppendEvent);
    expectedFilteredEvents.add(appendEvent);

    Event.UnlinkEvent unlinkEvent = new Event.UnlinkEvent.Builder()
        .path("/file")
        .build();
    Event.UnlinkEvent ignoredUnlinkEvent = new Event.UnlinkEvent.Builder()
        .path("/ignored")
        .build();
    Collections.addAll(allEvents, unlinkEvent, ignoredUnlinkEvent);
    expectedFilteredEvents.add(unlinkEvent);

    Event[] filteredEvents = eventFilter.filterIgnored(allEvents.toArray(new Event[0]));
    Assert.assertArrayEquals(expectedFilteredEvents.toArray(new Event[0]), filteredEvents);
  }
}
