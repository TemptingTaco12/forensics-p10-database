# forensics-p6-database

## The project
This is a project for the Forensics class at Eurecom.
The goal of the project was to deign a database to store the hashes, file metadata and a pointer to external files for dynamic analysis and VT reports of malware. This should include a command line interface to query malware, add new entries and export files that match given criteria.

Existing solutions: there are so many other databases, I dont know what to write here...

The database is implemented using [neo4j](https://neo4j.com). We chose to use neo4j because it is a very scalable and flexible database implemention. It is a graph database with an expressive query language that has good options for handling big databases.
 



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
See https://www.docker.com/products/docker-desktop/for more information on how to use the Web Console.

#### Command Line Interface
Sthe script "query-db.py" can be used for querying the database.
To use the command line interface run
 - python 3 script query-db.py

Together with one of the following arguments:
 - --grab-hashes         Pass the name of a malware instance to retrieve the samples associated with this instance.   
 - --grab-instances      Pass the name of a malware type to retrieve associated malware instances.   
 - --packet-sizes-gte    Pass a number to retrieve the malware instances and their associated samples that have an average packet size                            across all of their processes greater than or equal to this number.


## Conclusion

