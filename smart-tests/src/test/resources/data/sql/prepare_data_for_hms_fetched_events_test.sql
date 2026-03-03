CREATE
DATABASE db0;

ALTER
DATABASE db0 SET DBPROPERTIES ('Date' = '2026-01-13');

DROP
DATABASE db0;

CREATE
DATABASE db1;

CREATE TABLE db1.t1
(
    i INT
);

ALTER TABLE db1.t1
    ADD COLUMNS (j STRING);

DROP TABLE db1.t1;

CREATE TABLE db1.clients
(
    id   INT,
    name STRING
) PARTITIONED BY (MONTH STRING);

ALTER TABLE db1.clients
    ADD PARTITION (MONTH='december');

ALTER TABLE db1.clients PARTITION (MONTH ='december') RENAME TO PARTITION (MONTH ='january');

ALTER TABLE db1.clients DROP PARTITION (MONTH='january');

CREATE FUNCTION sum_cols AS 'org.apache.hadoop.hive.ql.udf.generic.GenericUDFOPPlus';

DROP FUNCTION sum_cols;

CREATE TABLE students
(
    id    INT,
    name  STRING NOT NULL,
    email STRING DEFAULT 'unknown'
);

ALTER TABLE students
    ADD CONSTRAINT students_pk PRIMARY KEY (id) DISABLE NOVALIDATE;

CREATE TABLE students_data
(
    data_id    INT,
    student_id INT
);

ALTER TABLE students_data
    ADD CONSTRAINT students_data_fk FOREIGN KEY (student_id) REFERENCES students (id) DISABLE NOVALIDATE;

ALTER TABLE students_data DROP CONSTRAINT students_data_fk;

ALTER TABLE students DROP CONSTRAINT students_pk;

ALTER TABLE students
    ADD CONSTRAINT students_email_uk UNIQUE (email) DISABLE NOVALIDATE;

ALTER TABLE students DROP CONSTRAINT students_email_uk;

ALTER TABLE students
    ADD CONSTRAINT students_id_chk CHECK (id > 0) DISABLE NOVALIDATE;

ALTER TABLE students DROP CONSTRAINT students_id_chk;

DROP TABLE students;

DROP TABLE students_data;