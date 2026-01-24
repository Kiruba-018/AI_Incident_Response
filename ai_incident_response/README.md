# AI Incident Response Agent 

 > The AI Incident Response Agent is a smart, AI tool designed to help Security Operations Center (SOC) teams detect, analyze, and respond to cybersecurity incidents faster and smarter.This app is particularly designed to detect the slow port scan (a stealthy recconnaissance technique) form the firewall logs

This application uses AI (via LangGraph and Groq LLM) to process firewall logs, classify suspicious IPs, assess severity, and notify stakeholders with the evidence and generated professional incident reports. It's built for real-world SOC environments, with scalability and security in mind.

## Key Features

- **Log Analysis**: Parses and analyzes firewall logs in real-time to detect port scans and suspicious activity.
- **IP Classification**: Uses behavioral analysis to label IPs as normal, suspicious, or scanner. This classsification is based on the number of SYN, FIN scan attempts to closed TCP ports and the sensitive ports hit.
- **Severity Scoring**: Calculates risk levels based on scan attempts and sensitive ports
- **Report Generation**: Generates detailed Markdown reports tailored for security team, including MITRE ATT&CK mappings.
- **Policy Integration**: Retrieves and maps relevant SOC policies using Retrieval-Augmented Generation (RAG).
- **Stakeholder Notifications**: Sends automated emails with reports attached.

## Quick Start

1. **Clone and Navigate**:
   ```bash
   git clone https://github.com/your-repo/ai-incident-response-agent.git
   cd ai-incident-response-agent
   ```

2. **Set Up Environment**:
   - Install Python 3.10+ if you haven't.
   - Create a virtual environment: `python -m venv venv && source venv/bin/activate` (or `venv\Scripts\activate` on Windows).
   - Install dependencies: `pip install -e .`

3. **Configure Secrets**:
   - Copy `.env.example` to `.env` and fill in your API keys (see Configuration below).

4. **Run the App**:
   ```bash
   langgraph dev 
   ```
   
## Prerequisites

- **Python**: 3.10 or higher (for async support).
- **APIs**: Groq API key (for LLM), SerpAPI key (for web searches), SMTP credentials (for emails).
- **Storage**: ChromaDB (included) for vector storage;.


## Configuration

The app uses environment variables for security. Create a `.env` file in the root directory:

```env
# AI and Search APIs
GROQ_API_KEY=your-groq-api-key-here
SERPAPI_API_KEY=your-serpapi-key-here

# Email Notifications
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password
SECURITY_TEAM_EMAIL=team@yourcompany.com

# Optional: LangSmith for tracing 
LANGSMITH_API_KEY=lsv2-your-key

# Advanced: Recursion limit for LangGraph
RECURSION_LIMIT=50
```

- **Groq API**: Sign up at [groq.com](https://groq.com) for fast LLM access.
- **SerpAPI**: Get a key at [serpapi.com](https://serpapi.com) for web searches.
- **SMTP**: Use Gmail or your company's SMTP server. For Gmail, enable 2FA and generate an app password.
- **Security Tip**: Never commit `.env` to Git—add it to `.gitignore`.
