INSERT INTO file
("path", fid, length, block_replication, block_size, modification_time, access_time, is_dir, sid, "owner", owner_group, "permission", ec_policy_id)
VALUES('file1.txt', 888, 0, 3, 1048576, ${currentTime}, ${currentTime}, false, 0, 'ssm', 'supergroup', 420, 0);
INSERT INTO file
("path", fid, length, block_replication, block_size, modification_time, access_time, is_dir, sid, "owner", owner_group, "permission", ec_policy_id)
VALUES('file2.txt', 999, 0, 3, 1048576, ${currentTime}, ${currentTime}, false, 0, 'ssm', 'supergroup', 420, 0);

INSERT INTO file_access
(fid, access_time)
VALUES(888, ${currentTime});
INSERT INTO file_access
(fid, access_time)
VALUES(999, ${currentTime});
INSERT INTO file_access
(fid, access_time)
VALUES(999, ${currentTime});