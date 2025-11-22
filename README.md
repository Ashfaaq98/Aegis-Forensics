# 🛡️ Aegis: Digital Forensics Agent

Aegis is a specialized AI cyber analyst powered by **Groq** and operating within a secure **E2B Sandbox** environment. It provides a secure, isolated platform for analyzing suspicious files, network captures (PCAP), and potentially malicious URLs without risking the host machine.

## ✨ Key Features

* **Isolated Analysis:** All forensic tools (`clamscan`, `tshark`, `exiftool`, `pefile`, etc.) run in a disposable, secure cloud sandbox (E2B).
* **LLM Orchestration (Groq):** The Groq LLM handles conversational context and intelligently selects and executes the appropriate tool based on user intent (e.g., automatically calling `visit_url` for a link or `scan_file` for an uploaded executable).
* **Forensic Tool Suite:** Pre-installed tools for:
    * Web/Phishing Analysis (`visit_url`)
    * Malware Scanning (`scan_file` / ClamAV)
    * Network Traffic Inspection (`analyze_pcap` / tshark)
    * Metadata and Static Analysis (`extract_metadata`, `static_analysis`)

## 🚀 Setup and Installation

### Prerequisites

1.  **API Keys:**
    * **E2B API Key:** For provisioning the secure sandbox.
    * **Groq API Key:** For powering the conversational agent and tool orchestration.
2.  **Python:** Python 3.9+

### Steps

1.  **Clone the Repository:**
    ```bash
    git clone [your_repo_link]
    cd [your_repo_name]
    ```

2.  **Create Virtual Environment & Install Dependencies:**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows, use: .\venv\Scripts\activate
    pip install -r requirements.txt # Assuming you have a requirements file
    ```
    *(If you don't have a `requirements.txt`, you will need to install `streamlit`, `groq`, `e2b`, and `python-dotenv`.)*

3.  **Configure Environment Variables:**
    Create a file named `.env` in the root directory and add your keys:
    ```env
    GROQ_API_KEY="your_groq_api_key_here"
    E2B_API_KEY="your_e2b_api_key_here"
    ```

## 💻 Running the App

Start the Streamlit application from your terminal:

```bash
streamlit run app.py
```