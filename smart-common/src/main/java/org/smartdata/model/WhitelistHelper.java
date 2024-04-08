package org.smartdata.model;

import org.smartdata.utils.PathUtil;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * It's a helper for whitelist function. It's used in action and rule submit process.
 * Especially, SmallFileScheduler also use this helper for  distinguishing between
 * whitelist check and invalid small files exception.
 */
public class WhitelistHelper {
  private static final String COMPACT_ACTION_NAME = "compact";
  private static final String UNCOMPACT_ACTION_NAME = "uncompact";

  public static void validateCmdletPathCovered(
      CmdletDescriptor cmdletDescriptor,
      PathChecker pathChecker
  ) throws IOException {
    for (int actionIdx = 0; actionIdx < cmdletDescriptor.getActionSize(); actionIdx++) {
      String actionName = cmdletDescriptor.getActionName(actionIdx);
      Map<String, String> args = cmdletDescriptor.getActionArgs(actionIdx);
      //check in the SmallFileScheduler for small file action
      if (actionName.equals(COMPACT_ACTION_NAME)
          || actionName.equals(UNCOMPACT_ACTION_NAME)
          || !args.containsKey(CmdletDescriptor.HDFS_FILE_PATH)) {
        continue;
      }

      String filePath = args.get(CmdletDescriptor.HDFS_FILE_PATH);
      if (!pathChecker.isCovered(filePath)) {
        throw new IOException("Path " + filePath + " is not in the whitelist.");
      }
    }
  }

  public static void validatePathsCovered(
      List<String> paths, PathChecker pathChecker) throws IOException {
    if (pathChecker.getCoverDirs().isEmpty()) {
      return;
    }

    Optional<String> uncoveredPath = firstUncoveredPath(paths, pathChecker);
    if (uncoveredPath.isPresent()) {
      throw new IOException("Path " + uncoveredPath.get() + " is not in the whitelist.");
    }
  }

  private static Optional<String> firstUncoveredPath(List<String> paths, PathChecker pathChecker) {
    return paths.stream()
        .map(PathUtil::addPathSeparator)
        .filter(path -> !pathChecker.isCovered(path))
        .findFirst();
  }
}
