import os
import json
import logging
import tiktoken
from elasticsearch import Elasticsearch

# Configure logging
logger = logging.getLogger(__name__)

def setup_logging(level=logging.INFO):
    """Set up logging configuration."""
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

def create_es_client(host):
    """
    Create and return an Elasticsearch client.
    
    Args:
        host: Elasticsearch host URL
        
    Returns:
        Elasticsearch client or None if connection fails
    """
    try:
        client = Elasticsearch(host)
        logger.info(f"Connected to Elasticsearch at {host}")
        return client
    except Exception as e:
        logger.error(f"Failed to connect to Elasticsearch: {e}")
        return None

def get_current_index(es_client, prefix="threat_intel"):
    """
    Get the current index name from file or latest available index.
    
    Args:
        es_client: Elasticsearch client
        prefix: Index name prefix
        
    Returns:
        Current index name or None if not found
    """
    try:
        # First try to read from file
        with open("current_index.txt", "r") as f:
            index = f.read().strip()
            if index:
                logger.info(f"Using index from file: {index}")
                return index
    except FileNotFoundError:
        pass
    
    # If file not found, try to find latest index
    try:
        indices = es_client.indices.get_alias(index=f"{prefix}*")
        if indices:
            # Return the most recent index (highest timestamp)
            latest_index = sorted(list(indices.keys()))[-1]
            logger.info(f"Using latest index: {latest_index}")
            return latest_index
    except Exception as e:
        logger.error(f"Error finding indices: {e}")
    
    return None

def count_tokens(text, model="gpt-4"):
    """
    Count the number of tokens in a text string.
    
    Args:
        text: Text to count tokens for
        model: OpenAI model name
        
    Returns:
        Number of tokens
    """
    try:
        encoding = tiktoken.encoding_for_model(model)
        return len(encoding.encode(text))
    except Exception as e:
        logger.warning(f"Error counting tokens: {e}")
        # If tiktoken fails, use a rough approximation
        return len(text) // 4

def extract_relevant_data(data, query):
    """
    Extract only relevant parts of the data to reduce token count.
    
    Args:
        data: The full threat intel data
        query: The user query
    
    Returns:
        Dictionary with only the most relevant information
    """
    # Extract query keywords
    query_lower = query.lower()
    keywords = []
    for word in query_lower.split():
        if len(word) > 3:  # Only consider words longer than 3 chars as significant
            keywords.append(word)
    
    # Check if this is a specific group query
    specific_groups = []
    common_groups = ["oilrig", "apt29", "apt30", "naikon", "dragon", "ocean"]
    for group in common_groups:
        if group in query_lower:
            specific_groups.append(group)
    
    # Extract relevant information based on document type
    if isinstance(data, dict):
        result = {}
        
        # Handle Group Details format
        if "Group Details" in data:
            group_name = data["Group Details"].get("Group Name", "").lower()
            
            # If we're looking for specific groups and this isn't one of them, extract minimal info
            if specific_groups and all(group not in group_name.lower() for group in specific_groups):
                return {
                    "Group Name": data["Group Details"].get("Group Name", ""),
                    "Description": data["Group Details"].get("Description", "")
                }
            
            # For relevant groups, extract more information
            result["Group Details"] = data["Group Details"]
            
            # For Associated Groups, only include relevant ones if specific groups are mentioned
            if "Associated Groups" in data and specific_groups:
                relevant_assoc = []
                for group in data.get("Associated Groups", []):
                    if any(kw in json.dumps(group).lower() for kw in keywords + specific_groups):
                        relevant_assoc.append(group)
                if relevant_assoc:
                    result["Associated Groups"] = relevant_assoc
            
            # For TTPs, include a limited selection
            if "Tactics and Techniques" in data:
                # Take only the first 10 techniques
                result["Tactics and Techniques"] = data.get("Tactics and Techniques", [])[:10]
            
            # For Tools, include a limited selection
            if "Tools" in data:
                # Take only the first 5 tools
                result["Tools"] = data.get("Tools", [])[:5]
                
            return result
                
        # Handle flatter structure
        else:
            # For direct queries about specific groups, extract more information
            if specific_groups and all(group not in data.get("group_name", "").lower() for group in specific_groups):
                return {
                    "group_name": data.get("group_name", ""),
                    "description": data.get("description", "")
                }
            
            # Include basic information
            result["group_name"] = data.get("group_name", "")
            result["description"] = data.get("description", "")
            
            # Include tools and techniques selectively
            if "tactics_and_techniques" in data:
                result["tactics_and_techniques"] = data.get("tactics_and_techniques", [])[:10]
            
            if "tools_and_malware" in data:
                result["tools_and_malware"] = data.get("tools_and_malware", [])[:5]
                
            return result
    
    # If not a dictionary, return as is
    return data

def save_to_file(content, filename, directory="reports"):
    """
    Save content to a file.
    
    Args:
        content: Content to save
        filename: File name
        directory: Directory to save to
        
    Returns:
        Full path to the saved file
    """
    # Ensure directory exists
    os.makedirs(directory, exist_ok=True)
    
    # Save file
    filepath = os.path.join(directory, filename)
    with open(filepath, 'w') as f:
        f.write(content)
    
    return filepath

def load_json_file(filepath):
    """
    Load and parse a JSON file.
    
    Args:
        filepath: Path to the JSON file
        
    Returns:
        Parsed JSON data or None if error
    """
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error loading JSON file {filepath}: {e}")
        return None

def extract_group_names(threat_intel_data):
    """
    Extract group names from threat intelligence data.
    
    Args:
        threat_intel_data: List of threat intelligence documents
        
    Returns:
        Set of group names
    """
    group_names = set()
    
    for item in threat_intel_data:
        if isinstance(item, dict):
            # Handle Group Details format
            if "Group Details" in item:
                group_name = item["Group Details"].get("Group Name")
                if group_name:
                    group_names.add(group_name)
                    
            # Handle flat format
            elif "group_name" in item:
                group_name = item.get("group_name")
                if group_name:
                    group_names.add(group_name)
    
    return group_names

def generate_api_prompt(query, threat_intel):
    """
    Generate a prompt for the OpenAI API.
    
    Args:
        query: User query
        threat_intel: Threat intelligence data
        
    Returns:
        Prompt for the API
    """
    context_str = json.dumps(threat_intel, indent=2)
    
    prompt = f"""
    You are an expert cybersecurity analyst. I will provide you with a query about threat actors, 
    APT groups, or cybersecurity threats, along with relevant threat intelligence data.
    
    Your task is to analyze the data and generate a comprehensive analysis report that addresses 
    the query. The report should be well-structured and include the following sections:
    
    1. Executive Summary
    2. Group Overview (for each relevant group)
    3. Tactics, Techniques, and Procedures (TTPs)
    4. Tools and Malware Used
    5. Targeted Sectors and Victims
    6. Relationship with Other Threat Actors (if applicable)
    7. Recommended Mitigations
    8. References
    
    Query: {query}
    
    Threat Intelligence Data:
    {context_str}
    
    Generate a comprehensive analysis report in Markdown format.
    """
    
    return prompt