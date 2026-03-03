CREATE
DATABASE db1;
CREATE
DATABASE db2;

CREATE TABLE db1.clients
(
    id   INT,
    name STRING
) PARTITIONED BY (MONTH STRING);
CREATE TABLE db2.workers
(
    id   INT,
    name STRING
) PARTITIONED BY (MONTH STRING);

ALTER TABLE db1.clients
    ADD PARTITION (MONTH='december');
ALTER TABLE db2.workers
    ADD PARTITION (MONTH='december');

ALTER TABLE db1.clients PARTITION (MONTH ='december') RENAME TO PARTITION (MONTH ='january');
ALTER TABLE db2.workers PARTITION (MONTH ='december') RENAME TO PARTITION (MONTH ='january');

ALTER TABLE db1.clients DROP PARTITION (MONTH='january');
ALTER TABLE db2.workers DROP PARTITION (MONTH='january');

CREATE FUNCTION db1.sum_cols_db1 AS 'org.apache.hadoop.hive.ql.udf.generic.GenericUDFOPPlus';
CREATE FUNCTION db2.sum_cols_db2 AS 'org.apache.hadoop.hive.ql.udf.generic.GenericUDFOPPlus';

DROP FUNCTION db1.sum_cols_db1;
DROP FUNCTION db2.sum_cols_db2;

CREATE TABLE db1.students
(
    id    INT,
    name  STRING NOT NULL,
    email STRING DEFAULT 'unknown'
);
CREATE TABLE db2.pupils
(
    id    INT,
    name  STRING NOT NULL,
    email STRING DEFAULT 'unknown'
);

ALTER TABLE db1.students
    ADD CONSTRAINT students_pk PRIMARY KEY (id) DISABLE NOVALIDATE;
CREATE TABLE db1.students_data
(
    data_id    INT,
    student_id INT
);
ALTER TABLE db1.students_data
    ADD CONSTRAINT students_data_fk FOREIGN KEY (student_id) REFERENCES db1.students (id) DISABLE NOVALIDATE;
ALTER TABLE db2.pupils
    ADD CONSTRAINT pupils_pk PRIMARY KEY (id) DISABLE NOVALIDATE;
CREATE TABLE db2.pupils_data
(
    data_id  INT,
    pupil_id INT
);
ALTER TABLE db2.pupils_data
    ADD CONSTRAINT pupils_data_fk FOREIGN KEY (pupil_id) REFERENCES db2.pupils (id) DISABLE NOVALIDATE;

ALTER TABLE db1.students_data DROP CONSTRAINT students_data_fk;
ALTER TABLE db1.students DROP CONSTRAINT students_pk;
ALTER TABLE db2.pupils_data DROP CONSTRAINT pupils_data_fk;
ALTER TABLE db2.pupils DROP CONSTRAINT pupils_pk;

ALTER TABLE db1.students
    ADD CONSTRAINT students_email_uk UNIQUE (email) DISABLE NOVALIDATE;
ALTER TABLE db1.students
    ADD CONSTRAINT students_id_chk CHECK (id > 0) DISABLE NOVALIDATE;
ALTER TABLE db2.pupils
    ADD CONSTRAINT pupils_email_uk UNIQUE (email) DISABLE NOVALIDATE;
ALTER TABLE db2.pupils
    ADD CONSTRAINT pupils_id_chk CHECK (id > 0) DISABLE NOVALIDATE;

ALTER TABLE db1.students DROP CONSTRAINT students_email_uk;
ALTER TABLE db1.students DROP CONSTRAINT students_id_chk;
ALTER TABLE db2.pupils DROP CONSTRAINT pupils_email_uk;
ALTER TABLE db2.pupils DROP CONSTRAINT pupils_id_chk;