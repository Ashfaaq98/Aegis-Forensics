# backend.py
import os
import json
import logging
import base64
from typing import Dict, Optional, Any, Generator

from e2b import Sandbox
from groq import Groq
from dotenv import load_dotenv

# --- LOGGING SETUP ---
logger = logging.getLogger("AegisBackend")
logger.setLevel(logging.INFO)

if not logger.handlers:
    c_handler = logging.StreamHandler()
    c_format = logging.Formatter('%(levelname)s: %(message)s')
    c_handler.setFormatter(c_format)

    f_handler = logging.FileHandler('aegis_operations.log')
    f_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    f_handler.setFormatter(f_format)

    logger.addHandler(c_handler)
    logger.addHandler(f_handler)

load_dotenv()

groq_client = None
try:
    groq_api_key = os.getenv("GROQ_API_KEY")
    groq_client = Groq(api_key=groq_api_key)
    logger.info("Groq Client Initialized successfully.")
except Exception as e:
    groq_client = None
    logger.critical(f"Failed to initialize Groq Client: {e}")

SYSTEM_PROMPT = """
You are Aegis, a friendly, expert cyber analyst operating inside a secure E2B sandbox.
Speak naturally and helpfully — like a senior security engineer talking to a colleague.

Behavior rules:
- **USE THE PROVIDED TOOLS WHENEVER NECESSARY to perform analysis.** Never attempt to analyze a URL, file, or run a shell command without using the appropriate function.
- When a tool returns a result, summarize and analyze the output *conversationally* before providing the final answer.
- Ask clarifying questions if the user's intent is ambiguous.
- Never embed raw base64 image data in chat output.
- If the user is just making small talk, reply conversationally without using tools.
"""

class CyberAgent:
    def __init__(self, api_key_e2b: str, model_id: str):
        self.e2b_key = api_key_e2b
        self.model_id = model_id
        self.sandbox: Optional[Sandbox] = None
        self.last_uploaded_file: Optional[str] = None
        self.last_screenshot: Optional[bytes] = None  
        logger.info(f"Agent initialized with Model: {model_id}")

    def start_sandbox(self):
        """Starts the E2B sandbox synchronously."""
        if self.sandbox:
            logger.warning("Attempted to start sandbox, but it is already running.")
            return

        logger.info("Initializing E2B Sandbox...")
        try:
            
            self.sandbox = Sandbox(api_key=self.e2b_key)
            sandbox_id = getattr(self.sandbox, "sandbox_id", "<unknown>")
            logger.info(f"Sandbox Created. ID: {sandbox_id}")

            logger.info("Installing Forensic Suite...")

            try:
                self.sandbox.commands.run("sudo apt-get update -y", timeout=600000)
            except Exception as e:
                logger.warning(f"apt-get update warning: {e}")

            deps = "tshark exiftool curl wget net-tools nmap clamav"
            try:
                self.sandbox.commands.run(f"sudo DEBIAN_FRONTEND=noninteractive apt-get install -y {deps}", timeout=1200000)
            except Exception as e:
                logger.warning(f"Some package installs failed or were killed: {e}")

            try:
                self.sandbox.commands.run("pip3 install pefile playwright nest_asyncio", timeout=600000)
            except Exception as e:
                logger.warning(f"Python package installation warning: {e}")

            browser_deps = (
                "libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 "
                "libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 "
                "libgbm1 libasound2 libpangocairo-1.0-0 libpango-1.0-0"
            )
            try:
                self.sandbox.commands.run(f"sudo apt-get install -y {browser_deps}", timeout=1200000)
                self.sandbox.commands.run("playwright install --with-deps chromium", timeout=1800000)
            except Exception as e:
                logger.warning(f"Playwright or browser deps could not be installed: {e}")

            try:
                try:
                    self.sandbox.commands.run("sudo systemctl stop clamav-freshclam", timeout=10000)
                except Exception:
                    pass  # systemctl may not exist
                fresh_result = self.sandbox.commands.run("sudo freshclam", timeout=120000)
                fr_err = getattr(fresh_result, "stderr", "")
                if fr_err and "killed" in fr_err.lower():
                    logger.warning(f"Freshclam warning (possibly OOM/killed): {fr_err}")
                else:
                    logger.info("freshclam executed (see logs).")
            except Exception as e:
                logger.warning(f"Freshclam non-critical warning: {e}")

            logger.info("Sandbox Ready (Forensic Suite Loaded).")
        except Exception as e:
            logger.error("Critical Error starting Sandbox", exc_info=True)
            raise

    def stop_sandbox(self):
        if self.sandbox:
            sandbox_id = getattr(self.sandbox, "sandbox_id", "<unknown>")
            logger.info(f"Stopping Sandbox {sandbox_id}...")
            try:
                if hasattr(self.sandbox, "kill"):
                    self.sandbox.kill()
            except Exception as e:
                logger.warning(f"Error during sandbox kill: {e}")
            self.sandbox = None
            self.last_uploaded_file = None
            self.last_screenshot = None
            logger.info("Sandbox Shutdown complete.")

    def _run_python_script(self, script_content: str, timeout: int = 60000) -> Dict[str, str]:
        """Writes a python script to a file and runs it inside the sandbox, mimicking code interpreter."""
        try:
            try:
                self.sandbox.commands.run("mkdir -p /home/user", timeout=5000)
            except Exception:
                pass

            try:
                self.sandbox.files.write("temp_tool_script.py", script_content.encode("utf-8"))
            except Exception:
                self.sandbox.files.write("temp_tool_script.py", script_content)
            cmd = self.sandbox.commands.run("python3 temp_tool_script.py", timeout=timeout)
            stdout = getattr(cmd, "stdout", "") or ""
            stderr = getattr(cmd, "stderr", "") or ""
            return {"stdout": stdout, "stderr": stderr}
        except Exception as e:
            return {"stdout": "", "stderr": str(e)}

    def _get_tools_definition(self):
        return [
            {
                "type": "function",
                "function": {
                    "name": "visit_url",
                    "description": "Fetches HTTP headers and takes a screenshot of a URL for phishing analysis. Use this for ANY web-based analysis.",
                    "parameters": {
                        "type": "object",
                        "properties": {"url": {"type": "string"}},
                        "required": ["url"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "static_analysis",
                    "description": "Performs static analysis on a file (PE headers, strings). Only use this after a file has been uploaded.",
                    "parameters": {
                        "type": "object",
                        "properties": {"filename": {"type": "string"}},
                        "required": ["filename"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "analyze_pcap",
                    "description": "Analyzes a .pcap network capture file. Only use this after a file has been uploaded.",
                    "parameters": {
                        "type": "object",
                        "properties": {"filename": {"type": "string"}},
                        "required": ["filename"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "extract_metadata",
                    "description": "Extracts hidden metadata (EXIF) from image files. Only use this after a file has been uploaded.",
                    "parameters": {
                        "type": "object",
                        "properties": {"filename": {"type": "string"}},
                        "required": ["filename"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "scan_file",
                    "description": "Scans an uploaded file using ClamAV. Only use this after a file has been uploaded.",
                    "parameters": {
                        "type": "object",
                        "properties": {"filename": {"type": "string"}},
                        "required": ["filename"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "run_command",
                    "description": "Runs a shell command inside the sandbox. Only use this if the user explicitly requests a command to be run (e.g., 'run ls -l').",
                    "parameters": {
                        "type": "object",
                        "properties": {"command": {"type": "string"}},
                        "required": ["command"]
                    }
                }
            }
        ]

    def execute_tool(self, tool_name: str, args: Dict[str, Any]) -> str:
        if not self.sandbox:
            logger.error("Tool execution attempted without active Sandbox.")
            return "Error: Sandbox is not active."

        logger.info(f"Executing Tool: {tool_name} with args: {args}")

        try:
            if tool_name == "visit_url":
                url = args["url"]
                # curl headers (with short timeout)
                try:
                    cmd_headers = self.sandbox.commands.run(f"curl -I -L -k --max-time 10 '{url}'", timeout=15000)
                    headers_out = getattr(cmd_headers, "stdout", "") or ""
                except Exception as e:
                    headers_out = f"Failed to fetch headers: {e}"

                # Use Playwright to get a screenshot (via helper script)
                safe_url = url.replace("'", "\\'")
                script = f"""
import nest_asyncio
nest_asyncio.apply()
from playwright.sync_api import sync_playwright
import os, sys
try:
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=['--no-sandbox','--disable-setuid-sandbox'])
        page = browser.new_page()
        try:
            page.goto('{safe_url}', timeout=30000)
        except Exception:
            pass
        path = '/home/user/screenshot.png'
        try:
            page.screenshot(path=path)
            print("SCREENSHOT_SUCCESS")
        except Exception as e:
            print("SCREENSHOT_ERROR:", e)
        finally:
            try:
                browser.close()
            except Exception:
                pass
except Exception as e:
    print("PW_ERROR:", e)
"""
                exec_result = self._run_python_script(script, timeout=60000)
                image_status = "Screenshot not available."

                if "SCREENSHOT_SUCCESS" in exec_result.get("stdout", ""):
                    try:
                        file_data = self.sandbox.files.read("/home/user/screenshot.png", format="bytes")
                        self.last_screenshot = file_data  # stored privately
                        image_status = "📷 Screenshot captured and stored (not displayed in chat)."
                    except Exception as e:
                        image_status = f"Screenshot read error: {e}"

                return (
                    "### 🔍 Website Forensic Report\n"
                    f"**Target:** `{url}`\n\n"
                    "#### 📡 HTTP Headers\n"
                    "```http\n"
                    f"{headers_out}\n"
                    "```\n\n"
                    f"{image_status}"
                )

            elif tool_name == "static_analysis":
                filename = args['filename']
                script = (
                    "import os, sys\n"
                    f"filename = {json.dumps(filename)}\n"
                    "print('File Type:', os.popen('file ' + filename).read().strip())\n"
                    "print('\\n--- Suspicious Strings ---')\n"
                    "cmd = f\"strings {filename} | grep -E '([0-9]{1,3}\\.){3}[0-9]{1,3}|http' | head -n 10\"\n"
                    "print(os.popen(cmd).read())\n"
                    "try:\n"
                    "    import pefile\n"
                    "    pe = pefile.PE(filename)\n"
                    "    print('\\n--- PE Headers ---')\n"
                    "    # Using a simple representation for PE to avoid huge output\n"
                    "    print('Sections:', pe.FILE_HEADER.NumberOfSections)\n"
                    "    print('Entry Point:', hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))\n"
                    "except Exception as e:\n"
                    "    print('PE parsing error:', e)\n"
                )
                exec_result = self._run_python_script(script, timeout=120000)
                return f"### 🧬 Static Code Analysis\n```\n{exec_result.get('stdout','')}\n{exec_result.get('stderr','')}\n```"

            elif tool_name == "extract_metadata":
                filename = args['filename']
                try:
                    cmd = self.sandbox.commands.run(f"exiftool {json.dumps(filename)}", timeout=30000)
                    out = getattr(cmd, "stdout", "")
                except Exception as e:
                    out = f"Metadata extraction failed: {e}"
                return f"### 🕵️ Metadata Extraction\n```yaml\n{out}\n```"

            elif tool_name == "analyze_pcap":
                filename = args['filename']
                try:
                    cmd_http = self.sandbox.commands.run(
                        f"tshark -r {json.dumps(filename)} -Y http.request -T fields -e http.host -e http.request.uri | head -n 20",
                        timeout=60000
                    )
                    http_out = getattr(cmd_http, "stdout", "")
                except Exception as e:
                    http_out = f"HTTP extraction failed: {e}"

                try:
                    cmd_dns = self.sandbox.commands.run(
                        f"tshark -r {json.dumps(filename)} -Y dns.qry.name -T fields -e dns.qry.name | sort | uniq -c | sort -nr | head -n 20",
                        timeout=60000
                    )
                    dns_out = getattr(cmd_dns, "stdout", "")
                except Exception as e:
                    dns_out = f"DNS extraction failed: {e}"

                return (
                    "### 🦈 Network Traffic Analysis\n\n"
                    "**HTTP Requests (host + uri, top 20):**\n"
                    "```\n" + http_out + "\n```\n\n"
                    "**DNS Queries (top 20):**\n"
                    "```\n" + dns_out + "\n```\n"
                )

            elif tool_name == "scan_file":
                filename = args['filename']
                try:
                    cmd = self.sandbox.commands.run(f"clamscan --no-summary {json.dumps(filename)}", timeout=120000)
                    scan_out = getattr(cmd, "stdout", "")
                    scan_err = getattr(cmd, "stderr", "")
                except Exception as e:
                    scan_out = ""
                    scan_err = f"ClamAV scan failed: {e}"
                return f"### 🛡️ ClamAV Scan Result\n```\n{scan_out}\n{scan_err}\n```"

            elif tool_name == "run_command":
                command = args['command']
                try:
                    cmd = self.sandbox.commands.run(command, timeout=120000)
                    out = getattr(cmd, "stdout", "")
                    err = getattr(cmd, "stderr", "")
                except Exception as e:
                    out = ""
                    err = f"Command execution failed: {e}"
                return f"### 🖥️ Command Output\n```\nSTDOUT:\n{out}\n\nSTDERR:\n{err}\n```"

            else:
                logger.error(f"Unknown tool requested: {tool_name}")
                return f"Error: Unknown tool '{tool_name}'."
        except Exception as e:
            logger.exception("Tool execution error")
            return f"Execution error: {e}"

    def _save_uploaded_file_to_sandbox(self, uploaded_file) -> Optional[str]:
        """Save Streamlit UploadedFile to sandbox and return sandbox path or None."""
        if not uploaded_file:
            return None
        if not self.sandbox:
            return None

        local_name = uploaded_file.name
        sandbox_dir = "/home/user/uploaded"
        sandbox_path = f"{sandbox_dir}/{local_name}"

        try:

            try:
                self.sandbox.commands.run(f"mkdir -p {sandbox_dir}", timeout=5000)
            except Exception:
                pass

            file_bytes = uploaded_file.getvalue()
            # try write as bytes, fallback to text if necessary
            try:
                self.sandbox.files.write(sandbox_path, file_bytes)
            except Exception:
                # fallback to text write
                try:
                    self.sandbox.files.write(sandbox_path, file_bytes.decode("utf-8", errors="ignore"))
                except Exception as e:
                    logger.error(f"Failed to write uploaded file to sandbox: {e}")
                    return None

            self.last_uploaded_file = sandbox_path
            return sandbox_path
        except Exception as e:
            logger.error(f"Error saving uploaded file: {e}", exc_info=True)
            return None
            
    def chat(self, prompt: str, uploaded_file=None) -> Generator[Dict[str, str], None, None]:
        """
        Chat generator that routes user requests to the appropriate tool via LLM function calling.
        """
        yield {"type": "text", "content": "Processing your request..."}

        try:
            sandbox_path = None
            uploaded_file_info = ""
            if uploaded_file is not None:
                yield {"type": "text", "content": f"Got your file — uploading **{uploaded_file.name}** to the sandbox..."}
                sandbox_path = self._save_uploaded_file_to_sandbox(uploaded_file)
                if sandbox_path:
                    # Inform the LLM about the available file via the system prompt
                    uploaded_file_info = f"\n\n**Note to self**: The user has uploaded a file named '{uploaded_file.name}' available at sandbox path: `{sandbox_path}`. If a file-analysis tool is necessary, use this path. File type: {uploaded_file.type}."
                    yield {"type": "text", "content": f"File uploaded to sandbox at: `{sandbox_path}`"}
                else:
                    uploaded_file_info = "\n\n**Note to self**: File upload failed. Do not attempt file-related tools."
                    yield {"type": "text", "content": "Couldn't upload the file to the sandbox — I'll continue without it."}

            text = (prompt or "").strip()
            
            messages = [
                {"role": "system", "content": SYSTEM_PROMPT + uploaded_file_info}, 
                {"role": "user", "content": text}
            ]
            
            response = groq_client.chat.completions.create(
                model=self.model_id,
                messages=messages,
                tools=self._get_tools_definition() 
            )

            tool_calls = response.choices[0].message.tool_calls
            ai_reply = response.choices[0].message.content

            while tool_calls:
                if ai_reply:
                    yield {"type": "text", "content": ai_reply}

                tool_results = []
                for tool_call in tool_calls:
                    tool_name = tool_call.function.name
                    try:
                        args = json.loads(tool_call.function.arguments)
                    except json.JSONDecodeError:
                        args = {} 
                        
                    yield {"type": "text", "content": f"**Invoking tool:** `{tool_name}` with arguments: `{args}`"}
                    
                    # Tool execution
                    result = self.execute_tool(tool_name, args)
                    tool_results.append({
                        "tool_call_id": tool_call.id,
                        "output": result,
                        "tool_name": tool_name # Keep tool name for the message
                    })
                    
                    # Yield tool result back to the user
                    yield {"type": "text", "content": result}

                messages.append(response.choices[0].message) 
                for tool_result in tool_results:
                    messages.append({
                        "tool_call_id": tool_result["tool_call_id"],
                        "role": "tool",
                        "name": tool_result["tool_name"], 
                        "content": tool_result["output"],
                    })

                response = groq_client.chat.completions.create(
                    model=self.model_id,
                    messages=messages,
                    tools=self._get_tools_definition()
                )
                
                tool_calls = response.choices[0].message.tool_calls
                ai_reply = response.choices[0].message.content

            if ai_reply:
                yield {"type": "text", "content": ai_reply}
            elif not ai_reply and len(messages) == 2: # No tool call, no initial response, meaning the prompt was simple and Groq returned nothing.
                 yield {"type": "text", "content": "I'm sorry, I couldn't generate a conversational response for that input."}
            
            return

        except Exception as e:
            logger.exception("Chat handling error")
            # If Groq fails, fallback to a simpler conversational attempt.
            if groq_client:
                 try:
                     # Simple conversational reply without tools if the tool orchestration fails
                     completion = groq_client.chat.completions.create(
                        model=self.model_id,
                        messages=[
                            {"role": "system", "content": "You are Aegis, a friendly security engineer. Explain the error clearly."},
                            {"role": "user", "content": f"The LLM tool orchestration failed with this error: {e}. The user asked: '{prompt}'. Please apologize and explain the system error concisely."}
                        ],
                    )
                     yield {"type": "text", "content": completion.choices[0].message.content}
                     return
                 except Exception:
                     pass

            yield {"type": "text", "content": f"Internal error during chat: {e}"}
            return