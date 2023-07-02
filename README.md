# Forensics P6 - Neo4j Malware Database

## The project
This is a project for the Forensics class at Eurecom.
The goal of the project was to design a database to store the hashes, file metadata and a pointer to external files for dynamic analysis and VT reports of malware. This should include a command line interface to query malware, add new entries and export files that match given criteria.

There exists several malware databases available already, but not many for storing malware hashes, file metadata and external pointers for dynamic analysis and VT reports of malware. We did not find any databases that exactly fulfills these requirements, but a couple of examples of other malware databases are VirusShare and MalwareBazaar. In addition, research is currently being done across many cybersecurity professionals to see if graph databases are effective in storing and fulfilling analysis requirements of malware metadata (i.e. https://www.gdatasoftware.com/blog/2018/11/31203-malware-analysis-with-a-graph-database).

The database that we have decided to implement uses [neo4j](https://neo4j.com). Traditionally relational databases or nosql dstabases are the most common types to use for this kind of task, but we chose to use neo4j because it is a very scalable and flexible database implemention. It is a graph database with an expressive query language that has good options for handling big databases. Graph databases are also very good for handling data where the connection between the entities are of big importance. It makes it easier to find relationships between entities, also when these relationships spans over several edges. In a graph database this can be done without using joins, which are computationally expensive. This makes graph databases a perfect fit for fulfilling the requirements for this project.

## How to use the database
### Prerequisites:
The user needs some software installed to use the database:
 - Python 3  https://www.python.org/downloads/
 - Docker Desktop  https://www.docker.com/products/docker-desktop/

### Installation:
To install the database run the following commands:
 - Clone the repository: git clone <link_to_repository>
 - Run the command: docker compose build
 - Followed by: docker compose up -d

To stop the data base run:
 - docker compose down

### Usage:

#### Web Console:
To explore the data via neo4j's Web Console, you can point your browser to localhost:7474.    
See https://www.docker.com/products/docker-desktop/ for more information on how to use the Web Console.

#### Command Line Interface
The script "query-db.py" can be used for querying the database.
To use the command line interface run
 - python 3 script query-db.py

Together with one of the following arguments to query information from the database:
|Option          |Description|
|--------------------------|-----------|
|--grab-hashes|Pass the name of a malware instance to retrieve the samples associated with this instance.|   
|--grab-instances|Pass the name of a malware type to retrieve the associated malware instances.|
|--packet-sizes-gte|Pass a number to retrieve the malware instances and their associated samples that have an average packet size across all of their processes greater than or equal to this number.|
|--search-malware-hash|Pass a malware hash to retrieve malware instance and type.|

Or together with all of these options to add an entry:

|Option          |Description|
-----------------|-----------|
|--add-malware-type|Used when wanting to add a new malware instance. Has the following format: --add-malware-type <malware_type>|
|--add-malware-instance|Used when wanting to add a new malware instance. Takes multiple arguments and has the following format: --add-malware-instance <malware_instance> <malware_type>|
|--add-sample|Used when wanting to add a new malware sample. Takes multiple arguments and has the following format: --add-hash <hash> <malware-instace>|
|--import-file|Used when wanting to import data from a csv file. Takes multiple arguments and has the following format: --import-file <file> <hash> <malware-instace> <malware-type>|
|--get-properties|Used to query for a sample based on its property values. To query, first specify the property then the value like this: --get-properties <property> <value>|

Or with this option to download processes:

|Option          |Description|
|----------------|-----------|
|--download-data|Used when wanting to add a new malware instance. Has the following format: --add-malware-type <malware_type>|

Note that input is case sensitive and should match the values of what is stored in the database in order to query back data.

## Conclusion
This database uses neo4j, which is a graph database, because of its qualities within efficiently finding relationships between entities and the good scalability that is available with this database.

Further work that could be done on this project is adding more queries for more functionality in the command line interface. In addition, we would also want to incorporate adding pointers to external documents and adding more input and error checking into the queries for the command line interface.

