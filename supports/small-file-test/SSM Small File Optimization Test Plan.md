SSM Small File Optimization Integration Test Plan
========================================

I. Hardware Configuration
----------------------------
Processor: 
DRAM:             
Network:               
Disks:             

II. Software Configuration
-----------------------------
1. Hadoop Configuration                 
 * Cluster:
 * Data Disks: 
 * Block Size:            
 * Version: 3.2.X / ADH 3.2.4_arenadata2_b1 or higher           

2. SSM Configuration                
 * Server Node             
 * Agents          

3. Other Configurations                 
 * Postgresql/ADPG 14 or higher                
 * Java: 1.8                   

### 1. Compact
#### Purpose
* Test the stability of small file compact rule and action.

#### Measurements
* Verify whether rule successfully executed.
* Execution time of compacting small files.

#### Data sets
Use [pyarrow_create_file.py](..%2Fintegration-test%2Fpyarrow_create_file.py) for generate data.
* a. Small files: 10MB * [100, 500, 1000, 10000, 50000] files
* b. Tiny files: 1MB * [100, 500, 1000, 10000, 50000] files
* c. 10KB * [100, 500, 1000, 10000, 50000] files

#### Test cases
* a. Run small file compact rule only.
* b. Run small file compact rule and other rules like Data Mover, Data Sync simultaneously.
* c. Run small file compact rule, meanwhile, delete or append... the original small files.

### 2. Transparent Read

#### Purpose
* Test the availability and stability of transparent read to the upper-layer applications like HBase, Spark etc.

#### Measurements
* Verify whether tasks successfully executed.
* Execution time of tasks.
* Service metrics 

#### Data sets
Use [pyarrow_create_file.py](..%2Fintegration-test%2Fpyarrow_create_file.py) for generate data.
* a. Small files: 10MB * [100, 500, 1000, 10000, 50000] files
* b. Tiny files: 1MB * [100, 500, 1000, 10000, 50000] files
* c. 10KB * [100, 500, 1000, 10000, 50000] files

#### Test cases
* a. Run hadoop bench of Hibench before and after compaction.
* b. Run spark bench of Hibench before and after compaction. 
