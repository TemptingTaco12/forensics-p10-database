from neo4j import GraphDatabase
import os
import csv
import re
import time

time.sleep(30)

# Neo4j connection details
uri = "bolt://malware-db:7687"
#uri = "bolt://localhost:7687"
# Connect to Neo4j
driver = GraphDatabase.driver(uri)

# Function to create a Malware type node
def create_malware_type_node(tx, malware_type):
    query = '''
    CREATE (node1:Malware_Type {name: $malware_type})
    WITH node1
    MATCH (node2:Malware)
    CREATE (node1)-[r:IS_A]->(node2)
    '''

    tx.run(query, malware_type=malware_type)
    
# Function to create a Malware instance node
def create_malware_instance_node(tx, malware_instance, malware_type):
    query = '''
    CREATE (node1:Malware_Instance {name: $malware_instance})
    WITH node1
    MATCH (node2:Malware_Type)
    WHERE node2.name = $malware_type
    CREATE (node1)-[r:IS_A]->(node2)
    '''
    
    tx.run(query, malware_instance=malware_instance, malware_type=malware_type)

def parse_hash(file):
    start_index = file.rfind("-") + 1
    end_index = file.find(".pcap_ISCX.csv")
    hash = file[start_index:end_index]
    
    return hash

# Function to create a Sample node
def create_sample_node(tx, hash, malware_instance):
    query = '''
    CREATE (node1:Sample {hash: $hash})
    WITH node1
    MATCH (node2:Malware_Instance)
    WHERE node2.name = $malware_instance
    CREATE (node1)-[r:IS_A]->(node2)
    '''

    tx.run(query, hash=hash, malware_instance=malware_instance)

    return hash

def is_int(s):
    try:
        int(s)
        return True
    except ValueError:
        return False

def is_float(s):
    try:
        float(s)
        return True
    except ValueError:
        return False

def create_process_nodes(tx, csv_file, hash):
#    print(csv_file)
    with open(csv_file, 'r') as file:
        reader = csv.reader(file)

        # Read the first row
        headers = next(reader)
        # Do some string cleanup
        headers_cleaned = [re.sub(r'^_', '', value.lower().replace(' ', '_').replace('/', '_per_')) for value in headers]

        sample_data = next(reader)

        data_types = []

        for sample in sample_data:
            if is_int(sample):
                data_types.append("int")
            elif is_float(sample):
                data_types.append("float")
            else:
                data_types.append("string")
    
    query = "LOAD CSV WITH HEADERS FROM 'file:///"
    query += csv_file
    query += '''' AS row
WITH row WHERE '''
    
    for idx, header in enumerate(headers):
        if idx < len(headers) - 1:
            query += "row.`"
            query += header
            query += "` IS NOT NULL"
            if idx < len(headers) - 2:
                query += " AND "

    query += '''
CREATE (n:Process {'''

    for idx, header in enumerate(headers):
        if idx < len(headers) - 1:
            query += headers_cleaned[idx]
            query += ": row.`"
            query += header
            query += "`"
            if idx < len(headers) - 2:
                query += ", "
    
    query += "})"
    
    query += '''
WITH n
MATCH (sampleNode:Sample {hash: $hash})
CREATE (sampleNode)-[:PERFORMED]->(n)
'''
    
#    print(query)
    tx.run(query, hash=hash)            

# Folder path
datasets_path = "datasets"

with driver.session(database="malware-db") as session:
    session.run("CREATE (:Malware {name: 'Malware'})")

    # # Traverse folders and create nodes
    for malware_type in os.listdir(datasets_path):
        session.execute_write(create_malware_type_node, malware_type)

        for malware_instance in os.listdir(datasets_path + "/" + malware_type):
            session.execute_write(create_malware_instance_node, malware_instance, malware_type)

            for file in os.listdir(datasets_path + "/" + malware_type + "/" + malware_instance):
                hash = parse_hash(file)
                session.execute_write(create_sample_node, hash, malware_instance)
                session.execute_write(create_process_nodes, 
                                      datasets_path + "/" + malware_type + "/" + malware_instance + "/" + file, hash)

# Close the Neo4j driver
driver.close()