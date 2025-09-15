WITH new_file AS (
  INSERT INTO "file"
    ("path", length, block_replication, block_size, modification_time, access_time, is_dir, sid, "owner", owner_group, "permission", ec_policy_id)
  VALUES
    ('${filePath}', 0, 3, 1048576, ${currentTime}, ${currentTime}, false, 0, 'ssm', 'supergroup', 420, 0)
  RETURNING fid
)

INSERT INTO file_access (fid, access_time)
SELECT fid, ${currentTime}
FROM new_file;