# Cybersecurity Threat Intelligence Analyst

A powerful AI-driven cybersecurity threat intelligence analysis system that helps security professionals understand and respond to cyber threats. This system ingests structured threat intelligence data into an Elasticsearch database and uses AI to analyze and generate comprehensive reports.

![Cybersecurity Threat Intelligence Analyst](https://via.placeholder.com/800x400?text=Cybersecurity+Threat+Intelligence+Analyst)

## 🌟 Features

- **Structured Threat Intelligence Storage**: Securely stores threat intelligence data in Elasticsearch
- **AI-Powered Analysis**: Uses OpenAI to provide in-depth analysis of threat actors
- **Interactive UI**: Beautiful Streamlit interface for querying and visualizing threat data
- **Comprehensive Reports**: Generates detailed Markdown reports on threat actors
- **Smart Token Management**: Efficiently manages API token usage to avoid rate limits

## 🛠️ Architecture

The system consists of four main components:

1. **Threat Intelligence Ingestor** (`threat_intel_ingestor.py`): Processes and ingests JSON files into Elasticsearch
2. **Threat Intelligence Analyst** (`threat_intel_analyst.py`): Command-line tool for querying and analyzing data
3. **Streamlit UI** (`streamlit_app.py`): Web-based user interface for interactive analysis
4. **Utilities** (`threat_intel_utils.py`): Shared functionality used by other components

## 🚀 Installation

### Prerequisites
- Python 3.8+
- Docker (for running Elasticsearch)
- OpenAI API key

### Setup Steps

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/cybersecurity-analyst.git
   cd cybersecurity-analyst
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up Elasticsearch**
   ```bash
   docker-compose up -d
   ```

4. **Set your OpenAI API key**
   ```bash
   export OPENAI_API_KEY=your_openai_api_key
   ```

## 💻 Usage

### 1. Ingest Threat Intelligence Data

```bash
python threat_intel_ingestor.py G0049.json G0019.json G0018.json G0017.json G0013.json G0050.json
```

This will:
- Create a new Elasticsearch index
- Process and ingest all JSON files
- Store the index name in `current_index.txt`

### 2. Analyze Threat Intelligence (Command Line)

```bash
# List all available threat groups
python threat_intel_analyst.py --list-groups

# Process a specific query
python threat_intel_analyst.py "Explain who OilRig APT Group is and which sectors they target. Also relate them to APT29."

# Start interactive mode
python threat_intel_analyst.py
```

### 3. Start the Streamlit UI

```bash
streamlit run streamlit_app.py
```

Then open your browser to `http://localhost:8501` to access the UI.

## 📊 Example Queries

- "What are the TTPs used by APT30?"
- "Explain to me who is OilRig APT Group and which sectors they are targeting."
- "Compare the tools and malware used by OilRig and APT30."
- "What sectors does APT30 target and what malware do they use?"
- "Give me an overview of Naikon APT group and their targets."
- "What tools are used by APT32 and how do they compare to tools used by OilRig?"
- "Explain the relationship between APT30 and Naikon."

## 📂 Project Structure

```
cybersecurity-analyst/
├── streamlit_app.py           # Streamlit UI
├── threat_intel_ingestor.py   # Data ingestion script
├── threat_intel_analyst.py    # Command-line analysis tool
├── threat_intel_utils.py      # Shared utility functions
├── docker-compose.yml         # Docker configuration for Elasticsearch
├── reports/                   # Generated reports directory
├── requirements.txt           # Python dependencies
└── README.md                  # This file
```

## 🛡️ Example Report

Here's an excerpt from a sample report on the OilRig APT Group:

```markdown
# OilRig APT Group Analysis

## Executive Summary

OilRig (also known as APT34, Helix Kitten, and COBALT GYPSY) is a suspected Iranian threat group that has been active since at least 2014. This group primarily targets organizations in the Middle East, with a focus on the financial, government, energy, chemical, and telecommunications sectors. OilRig is known for conducting supply chain attacks, leveraging trust relationships between organizations to reach their primary targets.

## Group Overview

OilRig operates on behalf of the Iranian government, as indicated by infrastructure details containing references to Iran, the use of Iranian infrastructure, and targeting that aligns with Iranian national interests. The group uses a mix of custom and publicly available tools, with a focus on maintaining persistent access to victim networks.

...
```

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgements

- [MITRE ATT&CK](https://attack.mitre.org/) for threat intelligence frameworks
- [Elasticsearch](https://www.elastic.co/) for providing powerful search capabilities
- [OpenAI](https://openai.com/) for AI analysis capabilities
- [Streamlit](https://streamlit.io/) for the interactive UI framework