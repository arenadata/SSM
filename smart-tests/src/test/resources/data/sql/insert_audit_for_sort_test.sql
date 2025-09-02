INSERT INTO user_activity_event
(username, "timestamp", object_type, object_id, operation, "result", additional_info)
VALUES('aUser', 1756742684301, 'CMDLET', 444, 'START', 'SUCCESS', NULL);

INSERT INTO user_activity_event
(username, "timestamp", object_type, object_id, operation, "result", additional_info)
VALUES('bUser', 1756742719425, 'RULE', 555, 'CREATE', 'SUCCESS', NULL);

INSERT INTO user_activity_event
(username, "timestamp", object_type, object_id, operation, "result", additional_info)
VALUES('cUser', 1756742789640, 'RULE', 555, 'STOP', 'SUCCESS', NULL);

INSERT INTO user_activity_event
(username, "timestamp", object_type, object_id, operation, "result", additional_info)
VALUES('dUser', 1756742791368, 'RULE', 555, 'DELETE', 'SUCCESS', NULL);
