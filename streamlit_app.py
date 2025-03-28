import os
import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import json
import time
from datetime import datetime
import tiktoken
import markdown
from elasticsearch import Elasticsearch
from openai import OpenAI

# Configure the page
st.set_page_config(
    page_title="Cybersecurity Threat Analyst",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Configuration
ES_HOST = os.environ.get('ES_HOST', 'http://localhost:9200')
OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY')
OUTPUT_DIR = os.environ.get('OUTPUT_DIR', 'reports')
MAX_TOKENS = 6000  # Setting a conservative limit below the 10k rate limit

# Ensure output directory exists
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Add custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #1E88E5;
        text-align: center;
        margin-bottom: 1rem;
    }
    .sub-header {
        font-size: 1.5rem;
        color: #333;
        margin-bottom: 1rem;
    }
    .highlight {
        background-color: #f0f2f6;
        padding: 1.5rem;
        border-radius: 0.5rem;
        margin-bottom: 1rem;
    }
    .footer {
        text-align: center;
        margin-top: 3rem;
        color: #666;
        font-size: 0.8rem;
    }
    .success-message {
        background-color: #D4EDDA;
        color: #155724;
        padding: 1rem;
        border-radius: 0.5rem;
        margin-bottom: 1rem;
    }
    .error-message {
        background-color: #F8D7DA;
        color: #721C24;
        padding: 1rem;
        border-radius: 0.5rem;
        margin-bottom: 1rem;
    }
    .info-box {
        background-color: #E3F2FD;
        padding: 1rem;
        border-radius: 0.5rem;
        margin-bottom: 1rem;
    }
</style>
""", unsafe_allow_html=True)

# Custom functions
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
                return index
        except FileNotFoundError:
            # List available indices with 'threat_intel' prefix
            indices = self.es_client.indices.get_alias(index="threat_intel*")
            if indices:
                # Return the most recent index (highest timestamp)
                return sorted(list(indices.keys()))[-1]
            return "threat_intel_index"  # Fallback name
        
    def _create_es_client(self) -> Elasticsearch:
        """Create and return an Elasticsearch client."""
        try:
            client = Elasticsearch(ES_HOST)
            return client
        except Exception as e:
            st.error(f"Failed to connect to Elasticsearch: {e}")
            return None
            
    def _setup_ai(self):
        """Set up the OpenAI client."""
        if not OPENAI_API_KEY:
            st.warning("OPENAI_API_KEY environment variable is not set. Some features will be limited.")
            return None
            
        try:
            # Create client with the OpenAI API
            client = OpenAI(api_key=OPENAI_API_KEY)
            return client
        except Exception as e:
            st.error(f"Failed to initialize OpenAI API: {e}")
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
            st.error(f"Error listing groups: {e}")
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
        if not self.es_client:
            return []
            
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
                    
            return results
        except Exception as e:
            st.error(f"Error searching Elasticsearch: {e}")
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
        
        # If the context is too large, reduce it
        if token_count > MAX_TOKENS:
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
        
        # Use OpenAI to generate the analysis
        try:
            # Use GPT-3.5 Turbo for larger contexts
            model = "gpt-4" if prompt_tokens <= 6000 else "gpt-3.5-turbo-16k"
            
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
            return analysis
        except Exception as e:
            st.error(f"Error generating analysis with OpenAI: {e}")
            
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
        
        return md_file
        
    def process_query(self, query: str):
        """
        Process a user query and generate a report.
        
        Args:
            query: User query
            
        Returns:
            Analysis in Markdown format and path to saved file
        """
        # Search for relevant threat intelligence
        threat_intel = self.search_threat_intel(query)
        
        # Generate the analysis
        analysis = self.generate_analysis(query, threat_intel)
        
        # Save the report
        md_file = self.save_report(analysis, query)
        
        return analysis, md_file, threat_intel


# Initialize session state
if 'analyst' not in st.session_state:
    st.session_state.analyst = ThreatIntelAnalyst()
if 'history' not in st.session_state:
    st.session_state.history = []
if 'current_report' not in st.session_state:
    st.session_state.current_report = None
if 'current_file' not in st.session_state:
    st.session_state.current_file = None
if 'threat_intel' not in st.session_state:
    st.session_state.threat_intel = None

# Sidebar
with st.sidebar:
    st.markdown("## 🔒 Cybersecurity Analyst")
    st.markdown("---")
    
    # Show available groups
    st.markdown("### Available Threat Groups")
    groups = st.session_state.analyst.list_available_groups()
    
    if groups:
        selected_group = st.selectbox("Select a group to include in your query:", 
                                     [""] + groups)
        
        if selected_group:
            st.markdown(f"**Selected Group:** {selected_group}")
            
            # Quick query buttons
            st.markdown("### Quick Queries")
            
            if st.button(f"Overview of {selected_group}"):
                query = f"Provide a comprehensive overview of {selected_group}."
                st.session_state.query = query
                st.rerun()
                
            if st.button(f"TTPs used by {selected_group}"):
                query = f"What tactics, techniques, and procedures (TTPs) does {selected_group} use?"
                st.session_state.query = query
                st.rerun()
                
            if st.button(f"Tools used by {selected_group}"):
                query = f"What tools and malware does {selected_group} use?"
                st.session_state.query = query
                st.rerun()
                
            if st.button(f"Targets of {selected_group}"):
                query = f"What sectors and regions does {selected_group} target?"
                st.session_state.query = query
                st.rerun()
    else:
        st.warning("No threat groups found in the database.")
    
    # History
    st.markdown("### Query History")
    if st.session_state.history:
        for i, (past_query, timestamp) in enumerate(st.session_state.history[:10]):  # Show last 10
            if st.button(f"{past_query[:30]}...", key=f"history_{i}"):
                st.session_state.query = past_query
                st.rerun()
    else:
        st.markdown("No history yet.")
    
    st.markdown("---")
    st.markdown("### About")
    st.markdown("This tool uses AI to analyze threat intelligence data stored in Elasticsearch.")
    st.markdown("© 2025 Cybersecurity Analyst")

# Main content
st.markdown('<h1 class="main-header">🔒 Cybersecurity Threat Intelligence Analyst</h1>', unsafe_allow_html=True)

# Query input
query = st.text_area("Enter your query about cyber threat actors:", 
                    value=st.session_state.get('query', ''),
                    height=100,
                    placeholder="Example: Explain to me who is OilRig APT Group and which sectors they are targeting. Also relate them to APT29.")

# Submit button with loading animation
if st.button("Analyze", type="primary"):
    if not query:
        st.error("Please enter a query.")
    else:
        with st.spinner("Analyzing threat intelligence data..."):
            # Add to history
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            if query not in [q for q, _ in st.session_state.history]:
                st.session_state.history.insert(0, (query, timestamp))
            
            # Process query
            try:
                analysis, file_path, threat_intel = st.session_state.analyst.process_query(query)
                st.session_state.current_report = analysis
                st.session_state.current_file = file_path
                st.session_state.threat_intel = threat_intel
                st.session_state.query = ""  # Clear input
                st.success(f"Analysis completed! Report saved to {file_path}")
                st.rerun()
            except Exception as e:
                st.error(f"An error occurred: {e}")

# Display current report
if st.session_state.current_report:
    st.markdown('<div class="highlight">', unsafe_allow_html=True)
    st.markdown(st.session_state.current_report)
    st.markdown('</div>', unsafe_allow_html=True)
    
    # Download button
    if st.session_state.current_file:
        with open(st.session_state.current_file, 'r') as f:
            report_content = f.read()
        
        st.download_button(
            label="Download Report (Markdown)",
            data=report_content,
            file_name=os.path.basename(st.session_state.current_file),
            mime="text/markdown"
        )
    
    # Show data visualization if we have threat intel
    if st.session_state.threat_intel:
        st.markdown('<h2 class="sub-header">Threat Intelligence Visualization</h2>', unsafe_allow_html=True)
        
        # Count and display the number of techniques by group
        techniques_by_group = {}
        tools_by_group = {}
        
        for item in st.session_state.threat_intel:
            group_name = None
            
            # Extract group name
            if isinstance(item, dict):
                if "Group Details" in item:
                    group_name = item["Group Details"].get("Group Name", "Unknown")
                elif "group_name" in item:
                    group_name = item.get("group_name", "Unknown")
            
            if not group_name:
                continue
                
            # Count techniques
            techniques = []
            if "Tactics and Techniques" in item:
                techniques = item.get("Tactics and Techniques", [])
            elif "tactics_and_techniques" in item:
                techniques = item.get("tactics_and_techniques", [])
            
            techniques_by_group[group_name] = len(techniques)
            
            # Count tools
            tools = []
            if "Tools" in item:
                tools = item.get("Tools", [])
            elif "tools_and_malware" in item:
                tools = item.get("tools_and_malware", [])
                
            tools_by_group[group_name] = len(tools)
        
        # Display visualizations in columns if we have data
        if techniques_by_group or tools_by_group:
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown('<div class="info-box">', unsafe_allow_html=True)
                st.subheader("Techniques by Group")
                if techniques_by_group:
                    # Create a simple bar chart
                    fig, ax = plt.subplots()
                    ax.bar(techniques_by_group.keys(), techniques_by_group.values(), color='skyblue')
                    ax.set_ylabel('Number of Techniques')
                    ax.set_title('TTPs by Threat Actor')
                    plt.xticks(rotation=45, ha='right')
                    plt.tight_layout()
                    st.pyplot(fig)
                else:
                    st.markdown("No technique data available.")
                st.markdown('</div>', unsafe_allow_html=True)
                
            with col2:
                st.markdown('<div class="info-box">', unsafe_allow_html=True)
                st.subheader("Tools by Group")
                if tools_by_group:
                    # Create a simple bar chart
                    fig, ax = plt.subplots()
                    ax.bar(tools_by_group.keys(), tools_by_group.values(), color='lightgreen')
                    ax.set_ylabel('Number of Tools')
                    ax.set_title('Tools & Malware by Threat Actor')
                    plt.xticks(rotation=45, ha='right')
                    plt.tight_layout()
                    st.pyplot(fig)
                else:
                    st.markdown("No tool data available.")
                st.markdown('</div>', unsafe_allow_html=True)
else:
    st.markdown('<div class="info-box">', unsafe_allow_html=True)
    st.markdown("""
    ## Welcome to the Cybersecurity Threat Intelligence Analyst

    This tool helps you analyze threat intelligence data using AI-powered insights. 
    
    To get started:
    1. Enter a query about cyber threat actors in the text box above
    2. Click the "Analyze" button
    3. Review the generated report
    
    You can also select a threat group from the sidebar to quickly generate specific reports.
    """)
    st.markdown('</div>', unsafe_allow_html=True)

    # Show example queries
    st.markdown('<h3 class="sub-header">Example Queries</h3>', unsafe_allow_html=True)
    example_queries = [
        "Explain to me who is OilRig APT Group and which sectors they are targeting.",
        "What are the TTPs used by APT30?",
        "Compare the tools and malware used by OilRig and APT30.",
        "What sectors does APT30 target and what malware do they use?",
        "Give me an overview of Naikon APT group and their targets."
    ]
    
    for query in example_queries:
        if st.button(query, key=f"example_{query[:20]}"):
            st.session_state.query = query
            st.rerun()

# Footer
st.markdown('<div class="footer">Cybersecurity Threat Intelligence Analyst ⋅ Powered by Streamlit and OpenAI</div>', unsafe_allow_html=True)