from neo4j import GraphDatabase
import argparse
import os
import csv
import re
import pandas as pd

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
parser.add_argument('--add-file', metavar='csv_file', type=str, 
    help='Pass in the path to the csv file containing information about the malware')
parser.add_argument('--add-hash', metavar='hash', type=str, 
    help='Pass in the hash of assosiated to a malware instance.')
parser.add_argument('--add-malware-instance', metavar='malware_instance', type=str, 
    help='Pass in the name of the malware instance.')
parser.add_argument('--add-malware-type', metavar='malware_type', type=str, 
    help='Pass in the name of the malware type.')
args = parser.parse_args()

# Check if any argument is provided
if not (
    args.grab_hashes or 
    args.grab_instances or 
    args.packet_sizes_gte or
    args.add_file or
    args.add_hash or
    args.add_malware_instance or
    args.add_malware_type
    ):
    print('''Please provide a valid argument. Use either: 
        --add-hash
        --add-malware-instance
        --add-malware-type
        --add-file
        --grab-hashes
        --grab-instances
        --packet-sizes-gte
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

#Helper function to check if number is int
def is_int(s):
    try:
        int(s)
        return True
    except ValueError:
        return False

#Helper function to check if number is float
def is_float(s):
    try:
        float(s)
        return True
    except ValueError:
        return False

#Function to add a new process node
def add_new_process(tx, malware_type, malware_instance, hash, csv_file):
    #check if the malware type exist, else make it 
    add_new_malware_type(tx, malware_type)

    #check if the malware instace exist, else make it.
    add_new_malware_instance(tx, malware_type, malware_instance)

    #add a new sample node if it does not exist.
    add_new_malware_sample(tx, malware_instance, hash)

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

        sample_data = next(reader)

        data_types = []

        for sample in sample_data:
            if is_int(sample):
                data_types.append("int")
            elif is_float(sample):
                data_types.append("float")
            else:
                data_types.append("string")
    
    df = pd.read_csv(csv_file)
    number_of_rows = len(df)
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
                MATCH (sampleNode:Sample {hash: $hash})
                CREATE (sampleNode)-[:PERFORMED]->(n)
                '''
        tx.run(query, hash=hash) 

    return True


def add_new_malware_instance(tx, malware_type, malware_instance):
    query = '''
            MERGE (node1:Malware_Instance {name: $malware_instance})
            WITH node1
            MATCH (node2:Malware_Type)
            WHERE node2.name = $malware_type
            MERGE (node1)-[r:IS_A]->(node2)
            '''
    tx.run(query, malware_instance=malware_instance, malware_type=malware_type)


def add_new_malware_type(tx, malware_type):
    query = '''
        MERGE (node1:Malware_Type {name: $malware_type})
        WITH node1
        MATCH (node2:Malware)
        MERGE (node1)-[r:IS_A]->(node2)
        '''
    tx.run(query, malware_type=malware_type)


def add_new_malware_sample(tx, malware_instance, hash):
    query = '''
            MERGE (node1:Sample {hash: $hash})
            WITH node1
            MATCH (node2:Malware_Instance)
            WHERE node2.name = $malware_instance
            MERGE (node1)-[r:IS_A]->(node2)
            '''

    tx.run(query, malware_instance=malware_instance, hash=hash)

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
            print("The malware type have been added")
        except:
            print("could not add the malware type, check your arguments and try again. Remember to add quotes around the malware type name")
    if args.add_malware_instance:
        try:
            session.execute_write(add_new_malware_instance, args.add_malware_type, args.add_malware_instance)
            print("The malware instance have been added")
        except:
            print("could not add the malware instance, check your arguments and try again. Remember to add quotes around the malware instance name") 
    if args.add_hash:
        try:
            session.execute_write(add_new_malware_sample, args.add_malware_instance, args.add_hash)
            print("The hash have been added")
        except:
            print("could not add the malware sample with hash, check your arguments and try again. Remember to add quotes around the hash") 
    if args.add_file:
        if not args.add_hash and not args.add_malware_instance and not args.add_malware_type:
            print("when adding a new process you also need to specify the hash using --add-hash, the name of the malware type using --add-malware-type, " + 
                  "and the name of the malware instance using --add-malware-instance")
        else:
            #try:
                res = session.execute_write(add_new_process, args.add_malware_type, args.add_malware_instance, args.add_hash, args.add_file)
                if res:
                    print("Successfully oploaded file")
                else:
                    print("Something went wrong, check that you uploaded the path to a csv file")
            #except:
                #print("An error occured, could not upload file")



# Close the Neo4j driver
driver.close()
