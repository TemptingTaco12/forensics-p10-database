# forensics-p6-database

## The project
This is a project for the Forensics class at Eurecom.
The goal of the project was to design a database to store the hashes, file metadata and a pointer to external files for dynamic analysis and VT reports of malware. This should include a command line interface to query malware, add new entries and export files that match given criteria.

There exists several malware databases available already, but not many for storing malware hashes, file metadata and external pointers for dynamic analysis and VT reports of malware. We did not find any databases that exactly fulfills these requirements, but a couple of examples of other malware databases are VirusShare and MalwareBazaar.

The database is implemented using [neo4j](https://neo4j.com). Traditionally relational databases or nosql dstabases are the most common types to use for this kind of task, but we chose to use neo4j because it is a very scalable and flexible database implemention. It is a graph database with an expressive query language that has good options for handling big databases. Graph databases are also very good for handling data where the connection between the entities are of big importance. It makes it easier to find relationships between entities, also when these relationships spans over several edges. In a graph database this can be done without using joins, which are computationally expensive. This makes graph databases a perfect fit for fulfilling the requirements for this project.
 

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

Together with one of the following arguments:
 - --grab-hashes         Pass the name of a malware instance to retrieve the samples associated with this instance.   
 - --grab-instances      Pass the name of a malware type to retrieve associated malware instances.   
 - --packet-sizes-gte    Pass a number to retrieve the malware instances and their associated samples that have an average packet size                            across all of their processes greater than or equal to this number.


## Conclusion
This database uses neo4j, which is a graph database, because of its qualities within efficiently finding relationships between entities and the good scalability that is available with this database.

Further work that could be done on this project is adding more queries for more functionality in the command line interface. Also, creating functionality to export data as a CSV file would be a good idea. As well as adding pointers to external documents.

