INSERT INTO "action"
(aid, cid, action_name, args, "result", log, successful, create_time, finished, finish_time, exec_host, progress, action_text, "source", start_time)
VALUES(0, 0, 'sleep', '{"-ms":"10"}', '', 'Action starts at Mon Aug 11 16:01:00 UTC 2025\n', true, 1754920000000, true, 1754920000000, 'SSMAgent@hadoop-datanode.aaa', 1.0, 'sleep -ms 10', 'USER', 1754920000000);

INSERT INTO "action"
(aid, cid, action_name, args, "result", log, successful, create_time, finished, finish_time, exec_host, progress, action_text, "source", start_time)
VALUES(1, 1, 'sleep', '{"-ruleId":"1","-file":"/","-ms":"10"}', '', 'Action starts at Mon Aug 11 16:01:00 UTC 2025\n', false, 1754921111111, true, 1754921111111, 'SSMAgent@hadoop-datanode.bbb', 1.0, 'sleep -ms 10', 'RULE', 1754921111111);

INSERT INTO "action"
(aid, cid, action_name, args, "result", log, successful, create_time, finished, finish_time, exec_host, progress, action_text, "source", start_time)
VALUES(2, 2, 'sleep', '{"-ms":"10"}', '', '', false, 1754922222222, false, NULL, NULL, 0.0, 'sleep -ms 10', 'USER', NULL);

INSERT INTO "action"
(aid, cid, action_name, args, "result", log, successful, create_time, finished, finish_time, exec_host, progress, action_text, "source", start_time)
VALUES(3, 3, 'sleep', '{"-ruleId":"1","-file":"/","-ms":"10"}', '', 'Action starts at Mon Aug 11 16:01:00 UTC 2025\n', true, 1754923333333, false, 1754923333333, 'SSMAgent@hadoop-datanode.ddd', 1.0, 'sleep -ms 10', 'RULE', 1754923333333);