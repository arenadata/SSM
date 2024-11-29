SELECT setval(pg_get_serial_sequence('file', 'fid'),
              COALESCE(MAX(fid), 0) + 1, false)
FROM file;