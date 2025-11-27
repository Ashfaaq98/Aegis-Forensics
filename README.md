# Aegis: Digital Forensics Agent

Aegis is a specialized AI cyber analyst powered by **Groq** and operating within a secure **E2B Sandbox** environment. It provides a secure, isolated platform for analyzing suspicious files, network captures (PCAP), and potentially malicious URLs without risking the host machine.

## Key Features

* **Isolated Analysis:** All forensic tools run in a disposable, secure cloud sandbox (E2B).

* **Forensic Tool Suite:** Pre-installed tools for:
    * Phishing  URL Analysis
    * Malware Scanning 
    * Network Traffic Analysis
    * Metadata Extraction
    * Static Malware Analysis
    * Dynamic Malware Analysis
    * Memory Forensics
    * File Carving
    * Hash Analysis
    * Behavioral Analysis

## Setup and Installation

### Prerequisites

1.  **API Keys:**
    * **E2B API Key:** For provisioning the secure sandbox.
    * **Groq API Key:** For powering the conversational agent and tool orchestration.
2.  **Python:** Python 3.9+

### Steps

1.  **Clone the Repository:**
    ```bash
    git clone https://github.com/Ashfaaq98/Aegis-Forensics.git
    cd Aegis-Forensics
    ```

2.  **Create Virtual Environment & Install Dependencies:**
    ```bash
    python -m venv venv
    source venv/bin/activate  
    pip install -r requirements.txt 
    ```

3.  **Configure Environment Variables:**
    Create a file named `.env` in the root directory and add your keys:
    ```env
    GROQ_API_KEY="your_groq_api_key_here"
    E2B_API_KEY="your_e2b_api_key_here"
    ```

## Running the App

Start the Streamlit application from your terminal:

```bash
streamlit run app.py
```