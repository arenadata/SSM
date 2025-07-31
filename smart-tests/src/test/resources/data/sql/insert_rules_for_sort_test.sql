INSERT INTO "rule"
("name", state, rule_text, submit_time, last_check_time, checked_count, generated_cmdlets, "owner")
VALUES(NULL, 1, 'file: every 1s | path matches "/*" | sleep -ms 100', 1753979334107, 1753979334107, 1, 1, 'john');

INSERT INTO public."rule"
("name", state, rule_text, submit_time, last_check_time, checked_count, generated_cmdlets, "owner")
VALUES(NULL, 0, 'file: every 1s | path matches "/*" | sleep -ms 100', 1753979625643, 1753979625643, 19, 19, 'john');