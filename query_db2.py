from neo4j import GraphDatabase
import argparse

# Parse command-line arguments
parser = argparse.ArgumentParser(
    description='Query the malware database to grab and print information on recorded malware as needed.')
parser.add_argument('--grab-hashes', metavar='malware_instance', type=str, 
    help='Pass the name of a malware instance to retrieve the samples associated with this instance.')
parser.add_argument('--grab-instances', metavar='malware_type', type=str, 
    help='Pass the name of a malware type to retrieve associated malware instances.')
parser.add_argument('--packet-sizes-gte', metavar='packet_size', type=int, 
    help='Pass a number to retrieve the malware instances and their associated samples that have ' +
    'an average packet size across all of their processes greater than or equal to this number.')
parser.add_argument('--search-malware-hash', metavar='malware_hash', type=str,
    help='Pass a malware hash to retrieve malware instance and type.')
args = parser.parse_args()

# Check if any argument is provided
if not (
    args.grab_hashes or 
    args.grab_instances or 
    args.packet_sizes_gte or
    args.search_malware_hash
    ):
    print('''Please provide a valid argument. Use either: 
        --grab-hashes
        --grab-instances
        --packet-sizes-gte
        --search-malware-hash''')
    exit()

# Neo4j connection details
uri = "bolt://localhost:7687"

# Connect to Neo4j
driver = GraphDatabase.driver(uri)

# Function to query and print sample hashes for a malware instance
def query_sample_hashes(tx, malware_instance):
    query = '''
    MATCH (:Malware_Instance {name: $malware_instance})<-[:IS_A]-(sample:Sample)
    RETURN sample.hash AS hash
    '''
    result = tx.run(query, malware_instance=malware_instance)
    hashes = [record["hash"] for record in result]
    return hashes

# Function to query and print malware instances for a malware type
def query_malware_instances(tx, malware_type):
    query = '''
    MATCH (:Malware_Type {name: $malware_type})<-[:IS_A]-(instance:Malware_Instance)
    RETURN instance.name AS malware_instance
    '''
    result = tx.run(query, malware_type=malware_type)
    instances = [record["malware_instance"] for record in result]
    return instances

# Function to query and print malware instances and associated hashes based on packet size
def query_malware_instances_with_packet_sizes(tx, packet_size):
    query = '''
    MATCH (process:Process)<-[:PERFORMED]-(sample:Sample)-[:IS_A]->(instance:Malware_Instance)
    WHERE process.average_packet_size >= $packet_size
    RETURN sample.hash AS hash, instance.name AS malware_instance, AVG(process.average_packet_size) AS avg_packet_size
    '''
    result = tx.run(query, packet_size=packet_size)
    instances_with_hashes = [(record["malware_instance"], record["avg_packet_size"], record["hash"]) for record in result]
    return instances_with_hashes

# Function to query and print malware instance and type of a give malware hash
def query_malware_instance_type_with_hash(tx, malware_hash):
    query = '''
    MATCH (:Malware_Hash {name: $malware_hash})<-[:IS_A]-(instance:Malware_Instance)
    RETURN instance.name AS malware_instance, type.name AS malware_type
    '''
    result = tx.run(query, malware_hash=malware_hash)
    instance_type = [(record["malware_instance"], record["malware_type"]) for record in result]
    return instances

# Execute the queries and print the results
with driver.session(database="malware-db") as session:
    if args.grab_hashes:
        hashes = session.execute_read(query_sample_hashes, args.grab_hashes)
        if hashes:
            print(f"Sample hashes for malware instance '{args.grab_hashes}':")
            for hash in hashes:
                print(hash)
        else:
            print(f"No sample hashes found for malware instance '{args.grab_hashes}'.")
    
    if args.grab_instances:
        instances = session.execute_read(query_malware_instances, args.grab_instances)
        if instances:
            print(f"Malware instances associated with malware type '{args.grab_instances}':")
            for instance in instances:
                print(instance)
        else:
            print(f"No malware instances found for malware type '{args.grab_instances}'.")
    
    if args.packet_sizes_gte:
        instances_with_hashes = session.execute_read(query_malware_instances_with_packet_sizes, args.packet_sizes_gte)
        if instances_with_hashes:
            print(f"Malware instances and their associated hashes with average packet sizes >= {args.packet_sizes_gte}:")
            for instance, avg_packet_size, hash in instances_with_hashes:
                print(f"Malware instance: {instance}")
                print(f"Sample hash: {hash}")
                print(f"Average packet size: {avg_packet_size}")
                print()
        else:
            print(f"No malware instances found with average packet sizes >= {args.packet_sizes_gte}.")
    
    if args.search_malware_hash:
        instance_type = session.execute_read(query_malware_instance_type_with_hash, args.search_malware_hash)
        if instance_type:
            print(f"Malware instance and type associated with malware hash '{args.search_malware_hash}':")
            for instance, type in instance_type:
                print(f"Malware instance: {instance}")
                print(f"Malware type: {type}")
        else:
            print(f"No malware instances or types found for malware hash '{args.search_malware_hash}'.")

# Close the Neo4j driver
driver.close()
