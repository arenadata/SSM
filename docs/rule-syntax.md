# Rule syntax

A rule defines all the things for SSM to work: at what time, to analyze what kind of metrics and conditions,
and what actions should be taken when the conditions are met.

By defining rules,
a user can easily manage cluster and adjust its behavior for certain purposes. A rule contains 4 parts.
The format is as follows:

```
Objects:  Trigger | Condition(s) | Action(s)
```

`Trigger` part is optional.  `:` and `|` are used to separate different
rule parts. These two characters are reserved by SSM, and cannot be used in rule
content, otherwise rule parse will fail.

| Example                                                                              | Description                                                                                                                                                                                               |
|--------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| file: path matches "/foo/\*\.dat" and accessCount\(7day\) &lt; 3 \| archive          | For each file with path matching the wildcard expression “/foo/\*\.dat”,<br>        if the file has been read for less than 3 times during the last 7 days,<br>        move the file to archive storage\. |
| file: path matches "/foo/\*" \| sync \-dest hdfs://ip:port/destdir                   | For each file with path matching the wildcard expression “/foo/\*\.dat”,<br>        incrementally sync it into "/destdir" of HDFS cluster denoted by 'ip:port'\.                                          |
| file: every 500ms \| path matches "/foo/\*" \| sync \-dest hdfs://ip:port/destdir    | The rule is as same as the above one except that the rule will be executed every 500ms \(by<br>        default the time interval is 5s\)\. In this way, the sync operation becomes more real\-time\.      |
| file: accessCount\(10min\) &lt; 2 \| archive                                         | If a file has been read for less than 2 times during the last 10 minutes,<br>        archive it\.                                                                                                         |
| file: at now\+30s \| path matches "/src1/\*" \| sync \-dest /dest1                   | After 30s from now, for files under /src1, sync them to /dest1\.                                                                                                                                          |
| file: at "2020\-06\-23 14:30:00" \| path matches "/src2/\*" \| sync \-dest /dest2    | At 2020\-06\-23 14:30:00, for files under /src2, sync them to /dest2\.                                                                                                                                    |
| file: every 5s \| path matches "/src3/\*" and length &lt; 1000 \| sync \-dest /dest3 | Every 5s to check the rule, for files under /src3 and whose length is smaller than 1000 bytes, sync them to /dest3/\.                                                                                     |

The following tables show detailed information about how to customize a SSM rule.

### Objects

| Object | Description                                                                       | Example                      |
|--------|-----------------------------------------------------------------------------------|------------------------------|
| file   | Specify files\. The most common used object is "file" to filter and manage data\. | path matches "/fooA/\*\.dat" |

### Triggers

| Format                               | Description                                                                          | Example                                                  |
|--------------------------------------|--------------------------------------------------------------------------------------|----------------------------------------------------------|
| at &lt;time&gt;                      | Execute the rule at the given time\. See the below Time table\.                      | at "2017\-07\-29 23:00:00"<br/>at now                    |
| every &lt;Time Interval&gt;          | Execute the rule at the given frequency\. See the below time table\.                 | every 1min                                               |
| from &lt;Time&gt;\[To &lt;Time&gt;\] | Along with 'every' expression to specify the time scope\. See the below time table\. | every 1day from now<br/>every 1min from now to now\+7day |

### Time

| Name          | Description                                         | Example                                                    |
|---------------|-----------------------------------------------------|------------------------------------------------------------|
| Time          | "yyyy\-MM\-dd HH:mm:ss:ms"<br/>Time \+ TimeInterval | "2017\-07\-29 23:00:00"<br/>now<br/>now\+7day              |
| Time Interval | Digital \+ unit <br/>Time \- Time                   | 5sec, 5min, 5hour, 5day<br/>now \- "2016\-03\-19 23:00:00" |

### Conditions

| Ingredient       | Description                                                                         | Example         |
|------------------|-------------------------------------------------------------------------------------|-----------------|
| Object Property  | Object property as subject of condition\. Refer to the above object property list\. | length &gt; 5MB |
| Logical operator | and, or, not                                                                        |                 |
| Digital operator | \+, \-, \*, /, %                                                                    |                 |
| Compare          | &gt;, &gt;=, &lt;, &lt;=, ==, \!=                                                   |                 |

### Object properties

| Object | Property                                                       | Abbreviation | Description                                                                                                                                               |
|--------|----------------------------------------------------------------|--------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------|
| file   | accessCount(interval)                                          | ac           | The access counts during the last time interval.                                                                                                          |
| file   | accessCountTop(interval,N)                                     | acTop        | The topmost N for access counts during the last time interval.                                                                                            |
| file   | accessCountBottom(interval,N)                                  | acBot        | The bottommost N for access counts during the last time interval.                                                                                         |
| file   | accessCountTopOnStoragePolicy(interval, N, "$StoragePolicy")   | acTopSp      | The topmost N for access counts with regard to a storage policy. The supported HDFS storage policies are COLD, WARM, HOT, ONE_SSD, ALL_SSD, LAZY_PERSIST. |
| file   | accessCountBottomOnStoragePolicy(interval,N, "$StoragePolicy") | acBotSp      | The bottommost N for access counts with regard to a storage policy during the last time interval.                                                         |
| file   | age                                                            | -            | The time span from last modification moment to now.                                                                                                       |
| file   | atime                                                          | -            | The last access time.                                                                                                                                     |
| file   | blocksize                                                      | -            | The block size of the file.                                                                                                                               |
| file   | ecPolicy                                                       | -            | The EC policy of the file.                                                                                                                                |
| file   | inCache                                                        | -            | The file is in cache storage.                                                                                                                             |
| file   | isDir                                                          | -            | The file is a directory.                                                                                                                                  |
| file   | length                                                         | -            | Length of the file. Bytes (KB, MB, GB, etc). Currently, only pure digital is supported, which indicates the number of bytes.                              |
| file   | mtime                                                          | -            | The last modification time of the file.                                                                                                                   |
| file   | path                                                           | -            | The file path in HDFS.                                                                                                                                    |
| file   | storagePolicy                                                  | -            | The storage policy of the file.                                                                                                                           |
| file   | unsynced                                                       | -            | The file is not synced.                                                                                                                                   |

### Actions

| SSM Action                                                                                                      |
|-----------------------------------------------------------------------------------------------------------------|
| All SSM actions can be used in SSM rules. Please refer to the [supported actions](./supported-actions.md) page. |
