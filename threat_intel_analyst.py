import os
import json
import logging
import argparse
import sys
import time
from datetime import datetime
import tiktoken
from elasticsearch import Elasticsearch
from openai import OpenAI

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configuration
ES_HOST = os.environ.get('ES_HOST', 'http://localhost:9200')
OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY')
OUTPUT_DIR = os.environ.get('OUTPUT_DIR', 'reports')
MAX_TOKENS = 6000  # Setting a conservative limit below the 10k rate limit

# Ensure output directory exists
os.makedirs(OUTPUT_DIR, exist_ok=True)

def count_tokens(text, model="gpt-4"):
    """Count the number of tokens in a text string."""
    try:
        encoding = tiktoken.encoding_for_model(model)
        return len(encoding.encode(text))
    except Exception:
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
    if "oilrig" in query_lower:
        specific_groups.append("oilrig")
    if "apt29" in query_lower:
        specific_groups.append("apt29")
    if "apt30" in query_lower:
        specific_groups.append("apt30")
    if "naikon" in query_lower:
        specific_groups.append("naikon")
    
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

class ThreatIntelAnalyst:
    """
    AI-powered cybersecurity analyst that uses Elasticsearch
    as a knowledge base and OpenAI for analysis.
    """
    
    def __init__(self, es_index=None):
        """Initialize the cybersecurity analyst."""
        self.es_client = self._create_es_client()
        self.client = self._setup_ai()
        self.es_index = es_index or self._get_index()
        
    def _get_index(self):
        """Get the index name from file or list available indices."""
        try:
            with open("current_index.txt", "r") as f:
                index = f.read().strip()
                logger.info(f"Using index: {index}")
                return index
        except FileNotFoundError:
            # List available indices with 'threat_intel' prefix
            indices = self.es_client.indices.get_alias(index="threat_intel*")
            if indices:
                # Return the most recent index (highest timestamp)
                latest_index = sorted(list(indices.keys()))[-1]
                logger.info(f"Using most recent index: {latest_index}")
                return latest_index
            
            logger.error("No index specified and no threat_intel indices found")
            sys.exit(1)
        
    def _create_es_client(self) -> Elasticsearch:
        """Create and return an Elasticsearch client."""
        try:
            client = Elasticsearch(ES_HOST)
            logger.info(f"Connected to Elasticsearch at {ES_HOST}")
            return client
        except Exception as e:
            logger.error(f"Failed to connect to Elasticsearch: {e}")
            sys.exit(1)
            
    def _setup_ai(self):
        """Set up the OpenAI client."""
        if not OPENAI_API_KEY:
            logger.warning("OPENAI_API_KEY environment variable is not set. Using basic report generation.")
            return None
            
        try:
            # Create client with the OpenAI API
            client = OpenAI(api_key=OPENAI_API_KEY)
            logger.info("Using OpenAI API")
            return client
        except Exception as e:
            logger.error(f"Failed to initialize OpenAI API: {e}")
            return None
    
    def list_available_groups(self):
        """List all available threat groups in the database."""
        try:
            # Query for all documents
            query = {
                "size": 100,  # Limit to 100 documents
                "query": {"match_all": {}}
            }
            
            response = self.es_client.search(index=self.es_index, body=query)
            
            groups = []
            for hit in response["hits"]["hits"]:
                source = hit["_source"]
                
                # Extract group name from different formats
                if "raw_json" in source:
                    try:
                        data = json.loads(source["raw_json"])
                        if "Group Details" in data:
                            group_name = data["Group Details"].get("Group Name", "")
                            if group_name:
                                groups.append(group_name)
                        elif "group_name" in data:
                            group_name = data.get("group_name", "")
                            if group_name:
                                groups.append(group_name)
                    except:
                        pass
                elif "group_name" in source:
                    group_name = source.get("group_name", "")
                    if group_name:
                        groups.append(group_name)
                elif "group_details" in source and "group_name" in source["group_details"]:
                    group_name = source["group_details"].get("group_name", "")
                    if group_name:
                        groups.append(group_name)
            
            # Return unique group names
            return sorted(list(set(groups)))
        except Exception as e:
            logger.error(f"Error listing groups: {e}")
            return []
        
    def search_threat_intel(self, query: str, size: int = 5):
        """
        Search for threat intelligence based on the query.
        
        Args:
            query: User query
            size: Maximum number of results to return
            
        Returns:
            List of relevant threat intelligence documents
        """
        # Extract potential APT group names from the query
        words = query.replace(',', ' ').replace('.', ' ').split()
        query_lower = query.lower()
        
        # If the query mentions specific groups, prioritize them
        specific_groups = []
        if "oilrig" in query_lower:
            specific_groups.append("oilrig")
        if "apt29" in query_lower:
            specific_groups.append("apt29")
        if "apt30" in query_lower:
            specific_groups.append("apt30")
        if "naikon" in query_lower:
            specific_groups.append("naikon")
        
        # Construct a simplified Elasticsearch query
        es_query = {
            "query": {
                "bool": {
                    "should": [
                        {"match": {"description": query}},
                        {"match": {"raw_json": query}}
                    ],
                    "minimum_should_match": 1
                }
            },
            "size": size
        }
        
        try:
            response = self.es_client.search(index=self.es_index, body=es_query)
            results = []
            
            for hit in response["hits"]["hits"]:
                source = hit["_source"]
                # Parse the raw_json field if it exists
                if "raw_json" in source:
                    try:
                        parsed_json = json.loads(source["raw_json"])
                        # Apply filtering to reduce token count
                        filtered_data = extract_relevant_data(parsed_json, query)
                        results.append(filtered_data)
                    except:
                        # If parsing fails, use the source as is
                        results.append(source)
                else:
                    results.append(source)
                    
            logger.info(f"Found {len(results)} threat intel documents")
            return results
        except Exception as e:
            logger.error(f"Error searching Elasticsearch: {e}")
            return []
            
    def generate_analysis(self, query: str, threat_intel):
        """
        Generate an analysis based on the user query and retrieved threat intelligence.
        
        Args:
            query: User query
            threat_intel: Retrieved threat intelligence
            
        Returns:
            Analysis in Markdown format
        """
        if not threat_intel:
            return "# Analysis Report\n\nNo relevant threat intelligence found for your query."
            
        if not self.client:
            return self._create_basic_report(query, threat_intel)
            
        # Create a context from the threat intel with token limit monitoring
        context_str = json.dumps(threat_intel, indent=2)
        token_count = count_tokens(context_str)
        logger.info(f"Initial context token count: {token_count}")
        
        # If the context is too large, reduce it
        if token_count > MAX_TOKENS:
            logger.warning(f"Context too large ({token_count} tokens). Reducing...")
            
            # Only keep the most relevant documents
            focused_intel = []
            query_lower = query.lower()
            
            # First priority: Documents explicitly about mentioned groups
            for doc in threat_intel:
                group_name = ""
                if isinstance(doc, dict):
                    if "Group Details" in doc:
                        group_name = doc["Group Details"].get("Group Name", "").lower()
                    else:
                        group_name = doc.get("group_name", "").lower()
                
                if any(group in group_name for group in ["oilrig", "apt29", "apt30", "naikon"] if group in query_lower):
                    focused_intel.append(doc)
            
            # If we don't have enough, add other relevant documents
            if len(focused_intel) < 2:
                for doc in threat_intel:
                    if doc not in focused_intel and len(focused_intel) < 3:
                        focused_intel.append(doc)
            
            # Update threat intel with focused selection
            threat_intel = focused_intel
            context_str = json.dumps(threat_intel, indent=2)
            token_count = count_tokens(context_str)
            logger.info(f"Reduced context token count: {token_count}")
        
        # Create a prompt for the AI
        prompt = f"""
        You are an expert cybersecurity analyst. I will provide you with a query about threat actors, APT groups, or cybersecurity threats, along with relevant threat intelligence data.
        
        Your task is to analyze the data and generate a comprehensive analysis report that addresses the query. The report should be well-structured and include the following sections:
        
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
        
        # Check if prompt is too large
        prompt_tokens = count_tokens(prompt)
        logger.info(f"Prompt token count: {prompt_tokens}")
        
        # Use OpenAI to generate the analysis
        try:
            # Use GPT-3.5 Turbo for larger contexts
            model = "gpt-4" if prompt_tokens <= 6000 else "gpt-3.5-turbo-16k"
            logger.info(f"Using model: {model}")
            
            # Create a chat completion with the OpenAI API
            response = self.client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": "You are an expert cybersecurity analyst specializing in threat intelligence."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2
            )
            analysis = response.choices[0].message.content
            logger.info("Generated analysis using OpenAI API")
            return analysis
        except Exception as e:
            logger.error(f"Error generating analysis with OpenAI: {e}")
            
            # Create a basic report if API call fails
            return self._create_basic_report(query, threat_intel)
                
    def _create_basic_report(self, query, threat_intel):
        """
        Create a basic report when OpenAI API fails.
        
        Args:
            query: User query
            threat_intel: Retrieved threat intelligence
            
        Returns:
            Basic analysis in Markdown format
        """
        logger.info("Generating basic report from available data")
        
        # Extract group names
        groups = {}
        for doc in threat_intel:
            if isinstance(doc, dict):
                if "Group Details" in doc:
                    group_name = doc["Group Details"].get("Group Name", "")
                    if group_name:
                        groups[group_name] = doc
                elif "group_name" in doc:
                    group_name = doc.get("group_name", "")
                    if group_name:
                        groups[group_name] = doc
        
        # Build a basic report
        report = [
            "# Threat Intelligence Analysis Report",
            "",
            "## Executive Summary",
            "",
            f"This report provides information about the threat actors mentioned in the query: '{query}'.",
            "Due to technical limitations, this is a basic report generated from available data.",
            "",
            "## Group Overviews",
            ""
        ]
        
        # Add group information
        for group_name, doc in groups.items():
            report.append(f"### {group_name}")
            report.append("")
            
            # Description
            if "Group Details" in doc:
                description = doc["Group Details"].get("Description", "No description available.")
                report.append(description)
            elif "description" in doc:
                description = doc.get("description", "No description available.")
                report.append(description)
            
            report.append("")
            
            # Techniques
            report.append("#### Tactics, Techniques, and Procedures")
            report.append("")
            
            if "Tactics and Techniques" in doc:
                techniques = doc.get("Tactics and Techniques", [])
                if techniques:
                    for i, technique in enumerate(techniques[:5]):  # Show at most 5
                        name = technique.get("Name", "Unknown Technique")
                        report.append(f"- {name}")
                else:
                    report.append("No specific techniques identified in the data.")
            else:
                report.append("No specific techniques identified in the data.")
                
            report.append("")
            
            # Tools
            report.append("#### Tools and Malware")
            report.append("")
            
            if "Tools" in doc:
                tools = doc.get("Tools", [])
                if tools:
                    for i, tool in enumerate(tools[:5]):  # Show at most 5
                        name = tool.get("Name", "Unknown Tool")
                        report.append(f"- {name}")
                else:
                    report.append("No specific tools identified in the data.")
            elif "tools_and_malware" in doc:
                tools = doc.get("tools_and_malware", [])
                if tools:
                    for i, tool in enumerate(tools[:5]):  # Show at most 5
                        name = tool.get("name", "Unknown Tool")
                        report.append(f"- {name}")
                else:
                    report.append("No specific tools identified in the data.")
            else:
                report.append("No specific tools identified in the data.")
                
            report.append("")
        
        # Add note about relation if specific groups are mentioned in the query
        query_lower = query.lower()
        if "oilrig" in query_lower and "apt29" in query_lower:
            report.append("## Relationship Between OilRig and APT29")
            report.append("")
            report.append("Based on the available data, both OilRig (believed to be Iranian-sponsored) and APT29 (believed to be Russian-sponsored) are sophisticated threat actors with distinct targeting profiles and toolsets. While both groups engage in cyber espionage, they appear to operate independently in support of their respective nation-state interests.")
            report.append("")
        
        # Add basic recommendations
        report.append("## Recommended Mitigations")
        report.append("")
        report.append("- Implement a robust patch management program to address known vulnerabilities")
        report.append("- Deploy endpoint detection and response (EDR) solutions")
        report.append("- Use email filtering and user awareness training to prevent phishing attacks")
        report.append("- Implement network segmentation and least-privilege access controls")
        report.append("- Regularly back up critical data and test restoration procedures")
        report.append("")
        
        # Add note about the report
        report.append("## Note")
        report.append("")
        report.append("This is a basic report generated due to API limitations. For a more comprehensive analysis, please try a more focused query or contact your threat intelligence provider.")
        
        return "\n".join(report)
    
    def save_report(self, analysis: str, query: str):
        """
        Save the analysis as a Markdown file.
        
        Args:
            analysis: Analysis in Markdown format
            query: User query
            
        Returns:
            Path to the Markdown file
        """
        # Generate a timestamp and sanitize the query for the filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        sanitized_query = query.lower().replace(' ', '_').replace('?', '').replace('!', '')[:30]
        base_filename = f"{timestamp}_{sanitized_query}"
        
        # Save the Markdown file
        md_file = os.path.join(OUTPUT_DIR, f"{base_filename}.md")
        with open(md_file, 'w') as f:
            f.write(analysis)
        logger.info(f"Saved Markdown report to {md_file}")
        
        return md_file
        
    def process_query(self, query: str):
        """
        Process a user query and generate a report.
        
        Args:
            query: User query
            
        Returns:
            Analysis in Markdown format and path to saved file
        """
        logger.info(f"Processing query: {query}")
        
        # Search for relevant threat intelligence
        threat_intel = self.search_threat_intel(query)
        
        # Generate the analysis
        analysis = self.generate_analysis(query, threat_intel)
        
        # Save the report
        md_file = self.save_report(analysis, query)
        
        return analysis, md_file


def main():
    """Main function to run the cybersecurity analyst."""
    parser = argparse.ArgumentParser(description='AI-powered cybersecurity analyst')
    parser.add_argument('query', nargs='?', help='Query about cybersecurity threats')
    parser.add_argument('--list-groups', action='store_true', help='List all available threat groups')
    parser.add_argument('--output-dir', help='Directory to save reports', default=OUTPUT_DIR)
    parser.add_argument('--es-host', help='Elasticsearch host URL', default=ES_HOST)
    parser.add_argument('--index', help='Elasticsearch index name')
    args = parser.parse_args()
    
    # Update configuration if provided
    global ES_HOST, OUTPUT_DIR
    ES_HOST = args.es_host
    OUTPUT_DIR = args.output_dir
    
    # Create output directory if it doesn't exist
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    # Initialize analyst
    analyst = ThreatIntelAnalyst(es_index=args.index)
    
    # List groups if requested
    if args.list_groups:
        groups = analyst.list_available_groups()
        if groups:
            print("\nAvailable Threat Groups:")
            for group in groups:
                print(f"- {group}")
        else:
            print("\nNo threat groups found in the database.")
        return
    
    # Process query if provided
    if args.query:
        print(f"\nProcessing query: {args.query}")
        print("This may take a moment...\n")
        
        try:
            analysis, file_path = analyst.process_query(args.query)
            
            print(f"Analysis completed!")
            print(f"Report saved to: {file_path}")
            
            # Ask if user wants to view the report
            view_report = input("\nWould you like to view the report? (y/n): ").strip().lower()
            if view_report == 'y':
                print("\n" + "="*80 + "\n")
                print(analysis)
                print("\n" + "="*80)
        except Exception as e:
            print(f"An error occurred: {e}")
    else:
        # Interactive mode
        if not args.list_groups:
            print("\nThreat Intelligence Analyst")
            print("-------------------------")
            
            while True:
                query = input("\nEnter your query (or 'exit' to quit): ")
                if query.lower() in ['exit', 'quit', 'q']:
                    break
                    
                if query:
                    print("\nProcessing query...")
                    try:
                        analysis, file_path = analyst.process_query(query)
                        
                        print(f"Analysis completed!")
                        print(f"Report saved to: {file_path}")
                        
                        # Ask if user wants to view the report
                        view_report = input("\nWould you like to view the report? (y/n): ").strip().lower()
                        if view_report == 'y':
                            print("\n" + "="*80 + "\n")
                            print(analysis)
                            print("\n" + "="*80)
                    except Exception as e:
                        print(f"An error occurred: {e}")


if __name__ == "__main__":
    main()