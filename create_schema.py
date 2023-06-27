from neo4j import GraphDatabase
import os

# Neo4j connection details
uri = "bolt://localhost:7687"
username = "neo4j"

# Function to create a Malware type node
def create_malware_type_node(tx, malware_type):
    query = '''
    CREATE (:Malware_Type {name: $malware_type})
    MATCH (node1:Malware_Type), (node2:Malware)
    WHERE node1.property = $malware_type
    CREATE (node1)-[r:IS_A]->(node2)
    '''
    
    tx.run(query, malware_type=malware_type)

# Function to create a Malware instance node
def create_malware_instance_node(tx, malware_instance):
    tx.run("CREATE (:Malware_Instance {name: $malware_instance})", malware_instance=malware_instance)

# Connect to Neo4j
driver = GraphDatabase.driver(uri)

# Folder path
datasets_path = "datasets"

with driver.session() as session:
    session.run("CREATE (:Malware)")

# # Traverse folders and create nodes
for malware_type in os.listdir(datasets_path):
    with driver.session() as session:
        session.execute_write(create_malware_type_node, malware_type)

    for malware_instance in os.listdir(datasets_path + "/" + malware_type):
        print(malware_instance)
        # Create node for each folder
        with driver.session() as session:
            session.execute_write(create_malware_instance_node, malware_instance)

# Close the Neo4j driver
driver.close()