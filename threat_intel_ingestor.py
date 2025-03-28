import os
import json
import logging
import argparse
import sys
import time
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def create_es_client(host):
    """Create and return an Elasticsearch client."""
    try:
        client = Elasticsearch(host)
        logger.info(f"Connected to Elasticsearch at {host}")
        return client
    except Exception as e:
        logger.error(f"Failed to connect to Elasticsearch: {e}")
        sys.exit(1)

def create_index(client, index_prefix):
    """Create a new index with minimal mapping and return its name."""
    # Create a timestamped index name
    index_name = f"{index_prefix}_{int(time.time())}"
    
    # Simplified mapping with minimal structure
    mapping = {
        "mappings": {
            "dynamic": True,  # Allow Elasticsearch to infer mappings
            "properties": {
                "document_type": {"type": "keyword"},
                "group_name": {"type": "keyword"},
                "description": {"type": "text"},
                "raw_json": {"type": "text"}  # Store the entire JSON as text
            }
        }
    }
    
    try:
        client.indices.create(index=index_name, body=mapping)
        logger.info(f"Created index {index_name} with minimal mapping")
        return index_name
    except Exception as e:
        logger.error(f"Error creating index: {e}")
        sys.exit(1)

def process_file(file_path):
    """Process a JSON file and extract key information."""
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        # Extract key information
        if "Group Details" in data:
            # MITRE ATT&CK format
            doc = {
                "document_type": "mitre_attack",
                "group_name": data["Group Details"].get("Group Name", ""),
                "group_id": data["Group Details"].get("Group ID", ""),
                "description": data["Group Details"].get("Description", ""),
                "raw_json": json.dumps(data)  # Store the entire JSON as a string
            }
        else:
            # Standard format
            doc = {
                "document_type": "standard",
                "group_name": data.get("group_name", ""),
                "description": data.get("description", ""),
                "raw_json": json.dumps(data)  # Store the entire JSON as a string
            }
        
        # Add source filename
        doc["source_file"] = os.path.basename(file_path)
        
        return doc
    except Exception as e:
        logger.error(f"Error processing file {file_path}: {e}")
        return None

def main():
    """Main function to process and ingest JSON files."""
    # Default configuration
    default_es_host = os.environ.get('ES_HOST', 'http://localhost:9200')
    default_index_prefix = 'threat_intel'
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Process and ingest JSON files into Elasticsearch')
    parser.add_argument('files', nargs='+', help='JSON files to process')
    parser.add_argument('--host', help='Elasticsearch host URL', default=default_es_host)
    parser.add_argument('--prefix', help='Index name prefix', default=default_index_prefix)
    args = parser.parse_args()
    
    # Create Elasticsearch client
    es_client = create_es_client(args.host)
    
    # Create new index
    index_name = create_index(es_client, args.prefix)
    
    # Process files
    documents = []
    for file_path in args.files:
        doc = process_file(file_path)
        if doc:
            # Generate a unique ID based on file name
            doc_id = os.path.splitext(os.path.basename(file_path))[0]
            
            # Create action for bulk API
            action = {
                "_index": index_name,
                "_id": doc_id,
                "_source": doc
            }
            
            documents.append(action)
            logger.info(f"Processed {file_path} -> {doc_id}")
    
    # Ingest documents
    if documents:
        try:
            success, errors = bulk(es_client, documents, refresh=True)
            logger.info(f"Successfully ingested {success} documents into {index_name}")
            if errors:
                logger.warning(f"Encountered {len(errors)} errors during ingestion")
                for error in errors:
                    logger.warning(f"Error: {error}")
                    
            # Save the index name to a file for easy reference
            with open("current_index.txt", "w") as f:
                f.write(index_name)
            logger.info(f"Saved index name to current_index.txt: {index_name}")
                
        except Exception as e:
            logger.error(f"Error during bulk ingestion: {e}")
            sys.exit(1)
    else:
        logger.warning("No documents to ingest")
    
    print(f"\nProcess completed successfully!")
    print(f"New index created: {index_name}")
    print(f"Index name saved to: current_index.txt")

if __name__ == "__main__":
    main()