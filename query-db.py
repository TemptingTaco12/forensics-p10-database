from neo4j import GraphDatabase
import argparse
import os
import csv
import re
import pandas as pd

# Parse command-line arguments
parser = argparse.ArgumentParser(
    description='Query the malware database to grab and print information on recorded malware as needed. NB! the queries are case sensitive')

parser.add_argument('--import-file', nargs="+", metavar='import_file', type=str,
    help='Used when wanting to import data from a csv file. Takes multiple arguments and has the following format: --import-file <file> <hash> <malware-instace> <malware-type>')
parser.add_argument('--add-sample', nargs="+", metavar='add_sample', type=str,
    help='Used when wanting to add a new malware sample. Takes multiple arguments and has the following format: --add-hash <hash> <malware-instace>')
parser.add_argument('--add-malware-instance', nargs="+", metavar='add_malware_instance', type=str,
    help='Used when wanting to add a new malware instance. Takes multiple arguments and has the following format: --add-malware-instance <malware_instance> <malware_type>')
parser.add_argument('--add-malware-type', metavar='add_malware_type', type=str,
    help='Used when wanting to add a new malware instance. Has the following format: --add-malware-type <malware_type>')
parser.add_argument('--download-data', nargs="+", metavar='download_data', 
    help='Download processes related to a sample. Takes multiple arguments and has the following format: --download-data <hash> <malware-instace> <malware-type>')
parser.add_argument('--get-properties', nargs="+", metavar='get_properties', type=str, 
    help="Used to query for a sample based on its property values. To query, first specify the property then the value like this: --get-properties <property> <value>")
parser.add_argument('--grab-hashes', metavar='malware_instance', type=str, 
    help='Pass the name of a malware instance to retrieve the samples associated with this instance.')
parser.add_argument('--grab-instances', metavar='malware_type', type=str, 
    help='Pass the name of a malware type to retrieve associated malware instances.')
parser.add_argument('--packet-sizes-gte', metavar='packet_size', type=int, 
    help='Pass a number to retrieve the malware instances and their associated samples that have ' +
    'an average packet size across all of their processes greater than or equal to this number.')
parser.add_argument('--search-malware-hash', metavar='malware_hash',
    help='Pass in the hash and retrieve the malware instance and malware type of that hash.')
args = parser.parse_args()

# Check if any argument is provided
if not (
    args.grab_hashes or 
    args.grab_instances or 
    args.packet_sizes_gte or
    args.import_file or
    args.add_sample or
    args.add_malware_instance or
    args.add_malware_type or 
    args.download_data or
    args.search_malware_hash or 
    args.get_properties
    ):
    print('''Please provide a valid argument. Use either: 
        --add-sample
        --add-malware-instance
        --add-malware-type
        --import-file
        --download-data
        --grab-hashes
        --grab-instances
        --packet-sizes-gte
        --search-malware-hash
        --get-properties
        ''')
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

#Function to add a new process node
def add_new_process(tx, malware_type, malware_instance, hash, csv_file):
    #check if the malware type exists 
    m_type = check_type(tx, malware_type)

    #check if the malware instance exists
    instance = check_instance(tx, malware_instance)

    #checks if sample node exists
    sample = check_sample(tx, hash)
    if not m_type or not instance or not sample:
        print("Some of the given paramenters does not exist. Check the spelling and try again.")
        return False

    #if file contains a hash column, then remove the column.
    df = pd.read_csv(csv_file)
    if "hash" in df.columns or "Hash" in df.columns:
        df.drop("hash", inplace=True, axis=1)

    #check if file is a csv file
    _, ext = os.path.splitext(csv_file)
    if not ext.lower() == '.csv':
        print("only except csv files")
        return False;
        
    #add the content of the csv file.
    with open(csv_file, 'r') as file:
        reader = csv.reader(file)
        # Read the first row
        headers = next(reader)
        # Do some string cleanup
        headers_cleaned = [re.sub(r'^_', '', value.lower().replace(' ', '_').replace('/', '_per_')) for value in headers]
    
    df = pd.read_csv(csv_file)
    query = ''''''
    counter = 0
    for index, row in df.iterrows():
        # Iterate over each column in the row
        query = '''
                CREATE (n:Process { '''
        for column_name, cell_value in row.items():
            # Access the header value for each column

            #header_value = df.columns[df.columns.get_loc(column_name)]
            header_value = headers_cleaned[counter]
            is_last_column = column_name == df.columns[-1]

            if type(cell_value)==int:
                cell_value = f'toInteger({cell_value})'
            elif type(cell_value)==float:
                cell_value = f'toFloat({cell_value})'
            else:
                cell_value = "'"+str(cell_value)+"'"

            if is_last_column:
                query += header_value + ": " + cell_value + " })"
                counter=0
            else:
                query += header_value + ":" + cell_value + ", "
                counter+=1

        query += '''
                WITH n
                MATCH (sampleNode:Sample {hash: $hash})-[:IS_A]->(instance:Malware_Instance {name: $malware_instance})-[:IS_A]->(type:Malware_Type {name: $malware_type})
                CREATE (sampleNode)-[:PERFORMED]->(n)
                '''
        tx.run(query, hash=hash, malware_type=malware_type, malware_instance=malware_instance) 

    return True


def add_new_malware_instance(tx, malware_type, malware_instance):
    if not check_type(tx, malware_type):
        print("The given malware type does not exist.")
        return False
    else:
        query = '''
                MERGE (node1:Malware_Instance {name: $malware_instance})
                WITH node1
                MATCH (node2:Malware_Type)
                WHERE node2.name = $malware_type
                MERGE (node1)-[r:IS_A]->(node2)
                '''
        tx.run(query, malware_instance=malware_instance, malware_type=malware_type)
        return True


def add_new_malware_type(tx, malware_type):
    query = '''
        MERGE (node1:Malware_Type {name: $malware_type})
        WITH node1
        MATCH (node2:Malware)
        MERGE (node1)-[r:IS_A]->(node2)
        '''
    tx.run(query, malware_type=malware_type)

#Function to check if the malware instance exist
def check_instance(tx, malware_instance):
    query = '''
            MATCH (n:Malware_Instance) 
            WHERE n.name = $malware_instance 
            RETURN EXISTS((n)--())
        '''
    result = tx.run(query, malware_instance=malware_instance)
    try:
        res = result.single()[0]
        return True
    except:
        return False

#Function to check if the malware type exist
def check_type(tx, malwareType):
    query = '''
            MATCH (n:Malware_Type) 
            WHERE n.name = $malwareType 
            RETURN EXISTS((n)--())
        '''
    result = tx.run(query, malwareType=malwareType)
    try:
        res = result.single()[0]
        return True
    except:
        return False

#Function to check if the malware sample exist
def check_sample(tx, hash):
    query = '''
            MATCH (n:Sample) 
            WHERE n.hash = $hash 
            RETURN EXISTS((n)--())
        '''
    result = tx.run(query, hash=hash)
    try:
        res = result.single()[0]
        return True
    except:
        return False

def add_new_malware_sample(tx, malware_instance, hash):
    if not check_instance(tx, malware_instance):
        print("The given malware instance does not exist")
        return False
    else:
        query = '''
                MERGE (node1:Sample {hash: $hash})
                WITH node1
                MATCH (node2:Malware_Instance)
                WHERE node2.name = $malware_instance
                MERGE (node1)-[r:IS_A]->(node2)
                '''

        tx.run(query, malware_instance=malware_instance, hash=hash)
        return True

#Function to export the properties of process nodes, related to a hash, into a csv file. 
def export_node_properties_to_csv(tx, malware_type, malware_instance, hash):
    csv_file = "./output.csv"

     #check if the malware type exists 
    m_type = check_type(tx, malware_type)

    #check if the malware instance exists
    instance = check_instance(tx, malware_instance)

    #checks if sample node exists
    sample = check_sample(tx, hash)
    if not m_type or not instance or not sample:
        print("Some of the given paramenters does not exist. Check the spelling and try again.")
        return False
   
    # Retrieve properties of nodes related to the sample
    query = '''
            MATCH (n)<-[:PERFORMED]-(n2:Sample { hash: $hash})-[:IS_A]->(instance:Malware_Instance {name: $malware_instance})-[:IS_A]->(type:Malware_Type {name: $malware_type})
            RETURN n'''
    result = tx.run(query, hash=hash, malware_type=malware_type, malware_instance=malware_instance)

    # Extract all unique property keys from the result
    property_keys = set()
    records = []
    for record in result:
        node = record["n"]
        property_keys.update(node.keys())
        records.append([node.get(value) for value in property_keys])

    # Write the data to the CSV file
    with open(csv_file, "w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=property_keys)
        writer.writeheader()

        # Write the data to the CSV file
        with open(csv_file, "w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(property_keys)  # Write the header row
            for record in records:
                writer.writerow(record)
    return True

# Function to query and print malware instance and type of a given malware hash
def query_malware_instance_type_with_hash(tx, hash):
    query = '''
    MATCH (n:Sample {hash: $hash})-[:IS_A]->(n2:Malware_Instance)-[:IS_A]->(n3:Malware_Type)
    RETURN n2.name AS malware_instance, n3.name AS malware_type
    '''
    result = tx.run(query, hash=hash)
    instance_type = [(record["malware_instance"], record["malware_type"]) for record in result]
    return instance_type

#Function to get hashes of all processes with a certain property.
def query_properties_of_nodes(tx, property, value):
    dots = r"\."
    pattern1 = fr".*([{dots}]).*[{dots}].*"
    special_chars = r"/|:|-"
    pattern2 = fr".*([{special_chars}]).*"
    query = ""
    if re.match(pattern1, value) or re.match(pattern2, value):
        query = "MATCH (n:Process)<-[:PERFORMED]-(n2:Sample) WHERE n.{property} = '{value}' RETURN DISTINCT n2.hash as sample_hashes".format(property=property, value=value)
    else:
        query = "MATCH (n:Process)<-[:PERFORMED]-(n2:Sample) WHERE n.{property} = {value} RETURN DISTINCT n2.hash as sample_hashes".format(property=property, value=value)
    result = tx.run(query)
    samples = [record["sample_hashes"] for record in result]
    return samples

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
    if args.add_malware_type:
        try:
            session.execute_write(add_new_malware_type, args.add_malware_type)
            print("The malware type has been added")
        except:
            print("Could not add the malware type. Check your arguments and try again.")
    if args.add_malware_instance:
            res = session.execute_write(add_new_malware_instance, args.add_malware_instance[1], args.add_malware_instance[0])
            if res:
                print("The malware instance has been added.")
            else:
                print("could not add the malware instance, check your arguments and try again.") 
    if args.add_sample:
        res = session.execute_write(add_new_malware_sample, args.add_sample[1], args.add_sample[0])
        if res:
            print("The hash has been added")
        else:
            print("Could not add the malware sample with hash. Check your arguments and try again.") 
    if args.import_file:
        try:
            res = session.execute_write(add_new_process, args.import_file[3], args.import_file[2], args.import_file[1], args.import_file[0])
            if res:
                print("Successfully uploaded the file.")
            else:
                print("Something went wrong, check that you uploaded the path to a csv file and spelled all parameters correctly.")
        except:
            print("An error occured. Could not upload file.")
    if args.download_data:
        try:
            res = session.execute_write(export_node_properties_to_csv, args.download_data[2], args.download_data[1], args.download_data[0])
            if res:
                print("Successfully uploaded the data to file. Check the output.csv file in the current directory.")
            else:
                print("Something went wrong. Check that you spelled all parameters correctly.")
        except:
            print("An error occured. Could not download file.")

    if args.search_malware_hash:
        instance_type = session.execute_read(query_malware_instance_type_with_hash, args.search_malware_hash)
        if instance_type:
            print(f"Malware instance and type associated with malware hash '{args.search_malware_hash}':")
            for instance, type in instance_type:
                print(f"Malware instance: {instance}")
                print(f"Malware type: {type}")
        else:
            print(f"No malware instances or types found for malware hash '{args.search_malware_hash}'.")

    if args.get_properties:
        samples = session.execute_read(query_properties_of_nodes, args.get_properties[0], args.get_properties[1])
        if samples:
            print(f"Samples hashes associated with the propety '{args.get_properties[0]}'='{args.get_properties[1]}':")
            for hash in samples:
                print(f"Sample hash: {hash}")
        else:
            print(f"No hashes are assosiated with the given property '{args.get_properties[0]}'='{args.get_properties[1]}'.")




# Close the Neo4j driver
driver.close()
