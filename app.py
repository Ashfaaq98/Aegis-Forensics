# app.py
import streamlit as st
import logging
from backend import CyberAgent
import os

logger = logging.getLogger("AegisFrontend")
logger.setLevel(logging.INFO)

if not logger.handlers:
    c_handler = logging.StreamHandler()
    f_handler = logging.FileHandler('aegis_operations.log')
    f_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    f_handler.setFormatter(f_format)
    logger.addHandler(c_handler)
    logger.addHandler(f_handler)

# --- Session State Initialization ---
if "messages" not in st.session_state:
    st.session_state.messages = [{"role": "assistant", "content": "Hello. I am Aegis. Please **Boot Sandbox** to begin an investigation."}]
if "agent" not in st.session_state:
    st.session_state.agent = None

st.set_page_config(page_title="Digital Forensics Agent", page_icon="🛡️", layout="wide")

with st.sidebar:
    st.title("🛡️ Aegis Control Panel")
    st.markdown("---")
    
    api_e2b = st.text_input("E2B API Key", value=os.getenv("E2B_API_KEY", ""), type="password", key="e2b_key_input")
    api_groq = st.text_input("Groq API Key", value=os.getenv("GROQ_API_KEY", ""), type="password", key="groq_key_input")
    
    selected_model = st.selectbox(
        "Select Groq Model",
        [
            "llama-3.3-70b-versatile",
            "llama-3.1-70b-versatile", 
            "mixtral-8x7b-32768"
        ],
        index=0,
        key="model_select"
    )
    
    st.divider()
    
    # --- Sandbox Management ---
    
    # Status Check
    is_agent_active = st.session_state.agent is not None and st.session_state.agent.sandbox is not None
    
    if not is_agent_active:
        if st.button("🚀 Boot Sandbox", help="Starts the isolated cloud environment"):
            if not api_e2b or not api_groq:
                st.error("Please enter both API keys.")
                logger.warning("User attempted boot without API keys.")
            else:
                try:
                    with st.spinner("Provisioning Secure Container (Installing Tools)..."):
                        agent = CyberAgent(api_e2b, selected_model)
                        agent.start_sandbox()
                        st.session_state.agent = agent
                        st.session_state.messages = [{"role": "assistant", "content": "✅ **System Online.** Aegis is ready to take commands."}]
                        st.success("System Online")
                        logger.info("Sandbox booted successfully.")
                        st.rerun()  # Rerun to update chat state cleanly
                except Exception as e:
                    st.error(f"Boot Failed: {e}")
                    logger.error(f"Boot process failed: {e}")
                    
    else:
        st.success("✅ System Active")
        if st.button("🔴 Shutdown Sandbox"):
            logger.info("User clicked Shutdown Sandbox.")
            try:
                st.session_state.agent.stop_sandbox()
            except Exception as e:
                logger.error(f"Error during sandbox kill: {e}")
            st.session_state.agent = None  
            st.session_state.messages = [{"role": "assistant", "content": "System Offline. Please **Boot Sandbox** to start a new session."}]
            st.rerun()

    st.divider()
    st.subheader("📂 Evidence Upload")

    uploaded_file = st.file_uploader("Upload Suspicious File", type=['txt', 'log', 'py', 'sh', 'pcap', 'exe', 'dll', 'elf', 'jpg', 'jpeg', 'png', 'gif', 'tiff', 'pdf'])
    if uploaded_file:
        logger.info(f"User uploaded file: {uploaded_file.name}")

st.title("Aegis: E2B Digital Forensics Agent")
st.markdown("A **Groq**-powered agent performing forensic analysis inside a secure **E2B Sandbox**.")

for msg in st.session_state.messages:
    with st.chat_message(msg["role"]):
        st.write(msg["content"])

if prompt := st.chat_input("Enter a URL to scan, file to check, or command to run..."):
    
    if st.session_state.agent is None:
        st.error("System Offline. Please Boot Sandbox in the Sidebar.")
        logger.warning("User input attempted without active agent (agent=None).")
        st.stop()
        
    is_sandbox_alive = st.session_state.agent.sandbox is not None
    if not is_sandbox_alive:
        # If the sandbox has timed out or disconnected, reset the agent gracefully.
        st.error("🚨 The secure sandbox connection was lost (timeout). Session Reset.")
        logger.error("Sandbox connection lost during user input. Resetting session state.")
        st.session_state.agent = None
        st.session_state.messages = [{"role": "assistant", "content": "🚨 **FATAL ERROR:** Sandbox connection lost. Please reboot the Sandbox to continue."}]
        st.rerun() 
        st.stop()
        
    logger.info(f"User Input: {prompt}")
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.write(prompt)

    with st.chat_message("assistant"):
        response_area = st.empty()
        full_text = ""

        try:
            chat_generator = st.session_state.agent.chat(prompt, uploaded_file)

            for update in chat_generator:

                if update.get("type") == "text":

                    full_text = update.get("content", "")
                    response_area.markdown(full_text)
                elif update.get("type") == "image":
                        # future image handling
                    b64 = update.get("content")
                    if b64:
                        response_area.image(b64)
        
        except Exception as e:
            st.error(f"Agent Error: {e}. Session Reset.")
            logger.error(f"Fatal Error during chat stream: {e}", exc_info=True)
            
            if st.session_state.agent and st.session_state.agent.sandbox:
                try:
                    st.session_state.agent.stop_sandbox()
                except Exception:
                    pass
                    
            st.session_state.agent = None
            st.session_state.messages = [{"role": "assistant", "content": "🚨 **FATAL ERROR:** Session crashed. Please reboot the Sandbox to continue."}]
            st.rerun()

        if full_text:
            st.session_state.messages.append({"role": "assistant", "content": full_text})
            logger.info("Response displayed to user.")