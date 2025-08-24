import os
from langchain_community.graphs import FalkorDBGraph

# --- Prerequisites ---
# To run this script, you must have a running FalkorDB instance.
# You can easily start one with Docker:
# docker run -p 6379:6379 -it --rm falkordb/falkordb:latest

# Define FalkorDB connection details. Using environment variables is a good practice.
FALKORDB_HOST = os.getenv("FALKORDB_HOST", "localhost")
FALKORDB_PORT = int(os.getenv("FALKORDB_PORT", 6379))


def create_cybersecurity_graph_data():
    """
    Initializes a FalkorDBGraph instance and populates it with sample
    cybersecurity infrastructure data based on the provided data model.
    This function simulates the ingestion of asset and permission data.
    """
    print(f"Connecting to FalkorDB at {FALKORDB_HOST}:{FALKORDB_PORT}...")
    try:
        # The FalkorDBGraph wrapper handles the database connection.
        graph = FalkorDBGraph(
            database="cyber_analysis",
            host=FALKORDB_HOST,
            port=FALKORDB_PORT
        )
        print("Connection successful.")

        # This multi-line Cypher query creates our sample graph. It includes
        # a malicious path (internet-exposed to sensitive data) and a benign
        # path for contrast. This is the "data model" part of the use case.
        #
        # Path 1 (The attack path):
        # IPRange -> SecurityGroup -> Compute (VM) -> IAMRole -> DataStore (S3)
        #
        # Path 2 (A benign path):
        # A non-internet-exposed Compute instance that also has a role, but the
        # path doesn't start from an internet-facing IP.
        
        creation_query = """
        // Malicious Path: Internet-exposed VM can access sensitive S3 data
        CREATE (internet:IPRange {cidr: '0.0.0.0/0', description: 'Public Internet'}),
               (sg_exposed:SecurityGroup {name: 'Web_Server_SG'}),
               (vm_exposed:Compute {id: 'i-exposed-web-01', platform: 'AWS EC2', type: 'Web Server'}),
               (role_s3:IAMRole {name: 'S3AccessRole', description: 'Allows read/write to sensitive data'}),
               (s3_sensitive:DataStore {name: 'sensitive-data-bucket', type: 'S3'}),
               (internet)-[:INGRESS_TO]->(sg_exposed)-[:ATTACHED_TO]->(vm_exposed),
               (vm_exposed)-[:ASSUMES]->(role_s3)-[:ALLOWS {actions: ['s3:GetObject', 's3:PutObject'], resource: 'arn:aws:s3:::sensitive-data-bucket/*'} ]->(s3_sensitive),

        // Benign Path: Internal VM with read-only access to a non-sensitive DB
        (sg_internal:SecurityGroup {name: 'Internal_SG'}),
        (vm_internal:Compute {id: 'i-internal-db-02', platform: 'AWS EC2', type: 'DB Instance'}),
        (role_rds:IAMRole {name: 'RDSReadOnlyRole'}),
        (db_non_sensitive:DataStore {name: 'app-db-prod', type: 'RDS'}),
        (sg_internal)-[:ATTACHED_TO]->(vm_internal),
        (vm_internal)-[:ASSUMES]->(role_rds)-[:ALLOWS {actions: ['rds:DescribeDBInstances'], resource: '*'}]->(db_non_sensitive)
        """
        
        print("Creating sample graph data...")
        graph.query(creation_query)
        print("Graph data created successfully.")
        
        # It's crucial to refresh the schema so LangChain's wrapper is aware of the
        # new node labels and relationship types we just created.
        graph.refresh_schema()
        print(f"Graph schema refreshed. New schema includes: {graph.schema}")

        return graph

    except Exception as e:
        print(f"An error occurred during graph creation: {e}")
        return None


def find_attack_paths(graph):
    """
    Executes a single Cypher query to find any "one-hop to pwn" attack paths.
    
    This function demonstrates the core value of the graph approach.
    Finding this path with tabular data would require multiple, complex SQL JOINs.
    In contrast, Cypher allows us to express this multi-hop relationship in a single,
    readable line of code.
    """
    if not graph:
        print("Graph connection is not available. Cannot perform query.")
        return

    print("\n--- Running attack path analysis ---")
    print("Searching for internet-exposed compute that can reach sensitive data via IAM...")
    
    # The elegant and powerful "single query" part of the use case.
    # The 'MATCH' clause specifies the exact pattern of nodes and relationships we're looking for.
    query_string = """
    MATCH (ip:IPRange {cidr: '0.0.0.0/0'}) // Start at the "internet" node
    -[:INGRESS_TO]->(:SecurityGroup) // Traverse to a SecurityGroup
    -[:ATTACHED_TO]->(c:Compute) // Find a Compute node attached to that group
    -[:ASSUMES]->(r:IAMRole) // Find the IAM role the compute assumes
    -[:ALLOWS]->(d:DataStore {name: 'sensitive-data-bucket'}) // Find the sensitive data store it has permissions to
    RETURN c.id, c.platform, r.name, d.name, d.type
    """
    
    try:
        # Execute the query and get the results.
        result = graph.query(query_string)
        
        if result:
            print("\n!!! DANGER: The following attack paths were found !!!")
            print("-" * 50)
            print(f"| {'Compute ID':<20} | {'Platform':<15} | {'IAM Role':<20} | {'DataStore':<20} |")
            print("-" * 50)
            for row in result:
                compute_id, platform, role_name, datastore_name, datastore_type = row
                print(f"| {compute_id:<20} | {platform:<15} | {role_name:<20} | {datastore_name:<20} |")
            print("-" * 50)
        else:
            print("No critical attack paths found in the current graph.")
            
    except Exception as e:
        print(f"An error occurred during query execution: {e}")


if __name__ == '__main__':
    # 1. First, create the graph structure and populate it with data.
    falkor_graph = create_cybersecurity_graph_data()
    
    # 2. Then, run the attack path analysis query on the created graph.
    if falkor_graph:
        find_attack_paths(falkor_graph)
