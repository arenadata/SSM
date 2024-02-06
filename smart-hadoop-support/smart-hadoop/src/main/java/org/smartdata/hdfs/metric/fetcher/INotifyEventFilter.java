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
package org.smartdata.hdfs.metric.fetcher;

import java.util.Arrays;
import org.apache.hadoop.hdfs.inotify.Event;
import org.smartdata.conf.SmartConf;
import org.smartdata.model.PathChecker;

public class INotifyEventFilter {
  private final PathChecker pathChecker;

  public INotifyEventFilter(PathChecker pathChecker) {
    this.pathChecker = pathChecker;
  }

  public INotifyEventFilter(SmartConf conf) {
    this.pathChecker = new PathChecker(conf);
  }

  public Event[] filterIgnored(Event[] events) {
    return Arrays.stream(events)
            .filter(event -> !shouldIgnore(event))
            .toArray(Event[]::new);
  }

  private boolean shouldIgnore(Event event) {
    String path;
    switch (event.getEventType()) {
      case CREATE:
        Event.CreateEvent createEvent = (Event.CreateEvent) event;
        path = createEvent.getPath();
        return shouldIgnorePath(path);
      case CLOSE:
        Event.CloseEvent closeEvent = (Event.CloseEvent) event;
        path = closeEvent.getPath();
        return shouldIgnorePath(path);
      case RENAME:
        Event.RenameEvent renameEvent = (Event.RenameEvent) event;
        path = renameEvent.getSrcPath();
        String dest = renameEvent.getDstPath();
        return shouldIgnorePath(path) && shouldIgnorePath(dest);
      case METADATA:
        Event.MetadataUpdateEvent metadataUpdateEvent = (Event.MetadataUpdateEvent) event;
        path = metadataUpdateEvent.getPath();
        return shouldIgnorePath(path);
      case APPEND:
        Event.AppendEvent appendEvent = (Event.AppendEvent) event;
        path = appendEvent.getPath();
        return shouldIgnorePath(path);
      case UNLINK:
        Event.UnlinkEvent unlinkEvent = (Event.UnlinkEvent) event;
        path = unlinkEvent.getPath();
        return shouldIgnorePath(path);
    }
    return true;
  }

  private boolean shouldIgnorePath(String path) {
    if (!path.endsWith("/")) {
      path = path + "/";
    }
    return pathChecker.isIgnored(path)
        || !pathChecker.isCovered(path);
  }
}
