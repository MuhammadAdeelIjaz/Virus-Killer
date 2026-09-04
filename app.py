import streamlit as st
import ipaddress
import re
import requests
import whois
import json
import time
from urllib.parse import urlparse
from datetime import datetime
import google.generativeai as genai
from typing import Dict, Any, Optional, Tuple, List

# ============================================================================
# 1. Imports and Configuration
# ============================================================================

# Page configuration
st.set_page_config(
    page_title="ThreatLens",
    page_icon="🛡️",
    layout="centered"
)

# API key validation - Updated for Streamlit Cloud
def check_api_keys():
    """Check if required API keys are available in secrets."""
    missing_keys = []
    
    # For Streamlit Cloud, secrets are accessed via st.secrets
    if not hasattr(st, 'secrets') or not st.secrets:
        return ["STREAMLIT_SECRETS"]
    
    if "VIRUSTOTAL_API_KEY" not in st.secrets or not st.secrets["VIRUSTOTAL_API_KEY"]:
        missing_keys.append("VIRUSTOTAL_API_KEY")
    if "GEMINI_API_KEY" not in st.secrets or not st.secrets["GEMINI_API_KEY"]:
        missing_keys.append("GEMINI_API_KEY")
    return missing_keys

# ============================================================================
# 2. Validation Helpers
# ============================================================================

def validate_ip(ip_str: str) -> bool:
    """Validate IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip_str.strip())
        return True
    except ValueError:
        return False

def validate_domain(domain_str: str) -> bool:
    """Validate domain name."""
    domain_str = domain_str.strip().lower()
    # Simple domain validation
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain_str))

def validate_url(url_str: str) -> bool:
    """Validate URL and extract domain."""
    url_str = url_str.strip()
    try:
        parsed = urlparse(url_str)
        if not parsed.scheme or not parsed.netloc:
            return False
        if parsed.scheme not in ['http', 'https']:
            return False
        # Extract domain from URL for further validation
        domain = parsed.netloc.split(':')[0]  # Remove port if present
        return validate_domain(domain) or validate_ip(domain)
    except Exception:
        return False

def extract_domain_from_url(url_str: str) -> Optional[str]:
    """Extract domain from URL."""
    try:
        parsed = urlparse(url_str.strip())
        domain = parsed.netloc.split(':')[0]
        return domain if domain else None
    except Exception:
        return None

def determine_target_type(target: str) -> str:
    """Determine the type of target (IP, Domain, URL)."""
    target = target.strip()
    
    if validate_ip(target):
        return "IP"
    elif validate_url(target):
        return "URL"
    elif validate_domain(target):
        return "Domain"
    else:
        return "Invalid"

# ============================================================================
# 3. Source Functions
# ============================================================================

def get_virustotal(target: str, target_type: str) -> Dict[str, Any]:
    """
    Query VirusTotal API for target intelligence.
    """
    # Get API key from secrets
    api_key = st.secrets.get("VIRUSTOTAL_API_KEY")
    if not api_key:
        return {
            "source": "VirusTotal",
            "status": "error",
            "data": {},
            "error": "VirusTotal API key not configured in Streamlit Cloud secrets"
        }
    
    # Build the appropriate URL based on target type
    base_url = "https://www.virustotal.com/api/v3"
    endpoint = ""
    encoded_target = target.strip()
    
    if target_type == "IP":
        endpoint = f"/ip_addresses/{encoded_target}"
    elif target_type == "Domain":
        endpoint = f"/domains/{encoded_target}"
    elif target_type == "URL":
        # For URLs, we need to use the URL ID format
        # URL ID is base64 encoded of the URL
        import base64
        url_bytes = encoded_target.encode('utf-8')
        url_id = base64.urlsafe_b64encode(url_bytes).decode('utf-8').rstrip('=')
        endpoint = f"/urls/{url_id}"
    else:
        return {
            "source": "VirusTotal",
            "status": "error",
            "data": {},
            "error": f"Unsupported target type: {target_type}"
        }
    
    headers = {
        "x-apikey": api_key,
        "Accept": "application/json"
    }
    
    try:
        response = requests.get(f"{base_url}{endpoint}", headers=headers, timeout=30)
        
        if response.status_code == 404:
            return {
                "source": "VirusTotal",
                "status": "error",
                "data": {},
                "error": "Target not found in VirusTotal database"
            }
        elif response.status_code == 429:
            return {
                "source": "VirusTotal",
                "status": "error",
                "data": {},
                "error": "Rate limit exceeded. Please try again later."
            }
        elif response.status_code != 200:
            return {
                "source": "VirusTotal",
                "status": "error",
                "data": {},
                "error": f"HTTP Error {response.status_code}: {response.text[:200]}"
            }
        
        data = response.json()
        
        # Extract relevant information
        result = {
            "source": "VirusTotal",
            "status": "success",
            "data": {},
            "error": None
        }
        
        if "data" in data:
            attributes = data["data"].get("attributes", {})
            
            # Extract statistical data
            stats = attributes.get("last_analysis_stats", {})
            result["data"]["stats"] = {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "timeout": stats.get("timeout", 0)
            }
            
            # Extract reputation
            result["data"]["reputation"] = attributes.get("reputation", 0)
            
            # Extract additional information based on type
            if target_type == "IP":
                result["data"]["country"] = attributes.get("country", None)
                result["data"]["as_owner"] = attributes.get("as_owner", None)
                result["data"]["asn"] = attributes.get("asn", None)
                
                # Network information
                network = attributes.get("network", None)
                if network:
                    result["data"]["network"] = network
            
            elif target_type == "Domain":
                result["data"]["categories"] = attributes.get("categories", {})
                result["data"]["creation_date"] = attributes.get("creation_date", None)
                result["data"]["last_update_date"] = attributes.get("last_update_date", None)
            
            elif target_type == "URL":
                result["data"]["url"] = attributes.get("url", None)
                result["data"]["categories"] = attributes.get("categories", {})
                result["data"]["last_analysis_date"] = attributes.get("last_analysis_date", None)
            
            # Get vendor detections (top 5 for readability)
            results = attributes.get("last_analysis_results", {})
            vendor_detections = []
            for vendor, detection in results.items():
                if detection.get("category") in ["malicious", "suspicious"]:
                    vendor_detections.append({
                        "vendor": vendor,
                        "category": detection.get("category"),
                        "result": detection.get("result", "Unknown")
                    })
            result["data"]["vendor_detections"] = vendor_detections[:10]  # Limit to 10
            
        else:
            result["status"] = "error"
            result["error"] = "Unexpected API response format"
        
        return result
        
    except requests.exceptions.Timeout:
        return {
            "source": "VirusTotal",
            "status": "error",
            "data": {},
            "error": "Request timed out. Please try again."
        }
    except requests.exceptions.ConnectionError:
        return {
            "source": "VirusTotal",
            "status": "error",
            "data": {},
            "error": "Connection error. Please check your internet connection."
        }
    except json.JSONDecodeError:
        return {
            "source": "VirusTotal",
            "status": "error",
            "data": {},
            "error": "Invalid response from API"
        }
    except Exception as e:
        return {
            "source": "VirusTotal",
            "status": "error",
            "data": {},
            "error": f"Unexpected error: {str(e)}"
        }


def get_whois(target: str, target_type: str) -> Dict[str, Any]:
    """
    Query WHOIS information for the target.
    """
    try:
        # Determine what to query based on target type
        if target_type == "URL":
            domain = extract_domain_from_url(target)
            if not domain:
                return {
                    "source": "WHOIS",
                    "status": "error",
                    "data": {},
                    "error": "Could not extract domain from URL"
                }
        elif target_type == "IP":
            # Some WHOIS lookups work for IPs, but many don't
            # We'll try but handle gracefully if it fails
            domain = target
        else:
            domain = target.strip()
        
        # Perform WHOIS lookup with timeout
        try:
            w = whois.whois(domain, timeout=10)
        except whois.parser.PywhoisError as e:
            # This is common when WHOIS is unavailable
            return {
                "source": "WHOIS",
                "status": "error",
                "data": {},
                "error": f"WHOIS lookup failed: {str(e)[:200]}"
            }
        
        # Check if we got valid data
        if not w or not w.domain_name:
            return {
                "source": "WHOIS",
                "status": "error",
                "data": {},
                "error": "No WHOIS data available for this target"
            }
        
        # Build normalized WHOIS result
        result = {
            "source": "WHOIS",
            "status": "success",
            "data": {},
            "error": None
        }
        
        # Extract data with proper handling for different formats
        result["data"]["domain_name"] = str(w.domain_name) if w.domain_name else "N/A"
        result["data"]["registrar"] = str(w.registrar) if w.registrar else "N/A"
        result["data"]["creation_date"] = str(w.creation_date) if w.creation_date else "N/A"
        result["data"]["expiration_date"] = str(w.expiration_date) if w.expiration_date else "N/A"
        result["data"]["updated_date"] = str(w.updated_date) if w.updated_date else "N/A"
        
        # Handle name servers (could be string or list)
        if w.name_servers:
            if isinstance(w.name_servers, list):
                result["data"]["name_servers"] = [str(ns) for ns in w.name_servers]
            else:
                result["data"]["name_servers"] = [str(w.name_servers)]
        else:
            result["data"]["name_servers"] = []
        
        result["data"]["org"] = str(w.org) if w.org else "N/A"
        result["data"]["country"] = str(w.country) if w.country else "N/A"
        
        # Handle status (could be string or list)
        if w.status:
            if isinstance(w.status, list):
                result["data"]["status"] = [str(s) for s in w.status]
            else:
                result["data"]["status"] = [str(w.status)]
        else:
            result["data"]["status"] = []
        
        # Handle emails
        if w.emails:
            if isinstance(w.emails, list):
                result["data"]["emails"] = [str(e) for e in w.emails]
            else:
                result["data"]["emails"] = [str(w.emails)]
        else:
            result["data"]["emails"] = []
        
        # Additional fields
        result["data"]["dnssec"] = str(w.dnssec) if w.dnssec else "N/A"
        
        return result
        
    except Exception as e:
        return {
            "source": "WHOIS",
            "status": "error",
            "data": {},
            "error": f"Unexpected WHOIS error: {str(e)}"
        }


# ============================================================================
# 4. SOURCES Registry
# ============================================================================

SOURCES = {
    "VirusTotal": get_virustotal,
    "WHOIS": get_whois,
}

# ============================================================================
# 5. Gemini Analysis
# ============================================================================

def build_gemini_prompt(target: str, target_type: str, knowledge_level: str, source_results: List[Dict[str, Any]]) -> str:
    """Build a level-specific prompt for Gemini."""
    
    # Prepare source data for the prompt
    source_data_str = json.dumps(source_results, indent=2)
    
    # Base instruction
    base_instruction = """
    You are a security intelligence analyst. Analyze the provided security data and provide a clear assessment.
    Use ONLY the data provided. Never invent information.
    If evidence is missing or conflicting, clearly state that.
    Do not claim something is "safe" simply because no malicious detections exist.
    Provide a JSON response with the following structure:
    {
      "verdict": "SAFE|SUSPICIOUS|MALICIOUS|UNKNOWN",
      "confidence": "High|Medium|Low",
      "summary": "Brief summary of the assessment",
      "key_findings": ["Finding 1", "Finding 2"],
      "risk_factors": ["Risk 1", "Risk 2"],
      "recommendations": ["Recommendation 1", "Recommendation 2"]
    }
    """
    
    # Level-specific instructions
    if knowledge_level == "Beginner":
        prompt = f"""
        {base_instruction}
        
        Use very simple, clear language. Explain any technical terms. Focus on key evidence and practical advice.
        
        Target: {target} (Type: {target_type})
        Knowledge Level: Beginner
        
        Source Data:
        {source_data_str}
        
        Provide your assessment in clear, simple language suitable for someone with no technical background.
        """
    elif knowledge_level == "Intermediate":
        prompt = f"""
        {base_instruction}
        
        Provide a balanced technical assessment. Include detection ratios, reputation scores, WHOIS information, and key vendor findings.
        
        Target: {target} (Type: {target_type})
        Knowledge Level: Intermediate
        
        Source Data:
        {source_data_str}
        
        Provide a practical risk assessment with recommendations.
        """
    else:  # Expert
        prompt = f"""
        {base_instruction}
        
        Provide a concise technical assessment covering:
        - IOC characteristics and detection consensus
        - WHOIS lifecycle and domain age considerations
        - Network/ASN information and its implications
        - Vendor detection patterns and confidence levels
        - Investigative recommendations
        
        Target: {target} (Type: {target_type})
        Knowledge Level: Expert
        
        Source Data:
        {source_data_str}
        
        Focus on technical details, confidence levels, and specific investigation steps.
        """
    
    return prompt


def analyze_with_gemini(target: str, target_type: str, knowledge_level: str, source_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Use Gemini to analyze the collected source data.
    """
    api_key = st.secrets.get("GEMINI_API_KEY")
    if not api_key:
        return {
            "verdict": "UNKNOWN",
            "confidence": "Low",
            "summary": "Gemini API key not configured in Streamlit Cloud secrets",
            "key_findings": ["API configuration error"],
            "risk_factors": [],
            "recommendations": ["Please configure Gemini API key in Streamlit Cloud settings"]
        }
    
    try:
        # Configure Gemini
        genai.configure(api_key=api_key)
        
        # FIXED: Use the correct model name
        # List of available models: gemini-1.5-pro, gemini-1.5-flash, gemini-1.0-pro, etc.
        # Use gemini-1.5-pro for better quality or gemini-1.5-flash for faster responses
        model = genai.GenerativeModel("gemini-1.5-flash")
        
        # Build the prompt
        prompt = build_gemini_prompt(target, target_type, knowledge_level, source_results)
        
        # Get response with generation config
        response = model.generate_content(
            prompt,
            generation_config=genai.types.GenerationConfig(
                temperature=0.1,
                top_p=0.95,
                top_k=40,
                max_output_tokens=8192,
            )
        )
        
        response_text = response.text.strip()
        
        # Try to parse JSON
        try:
            # Look for JSON in the response
            json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
            if json_match:
                json_str = json_match.group()
                result = json.loads(json_str)
                
                # Ensure all required fields exist
                if "verdict" not in result:
                    result["verdict"] = "UNKNOWN"
                if "confidence" not in result:
                    result["confidence"] = "Medium"
                if "summary" not in result:
                    result["summary"] = "Analysis completed but no summary provided"
                if "key_findings" not in result:
                    result["key_findings"] = []
                if "risk_factors" not in result:
                    result["risk_factors"] = []
                if "recommendations" not in result:
                    result["recommendations"] = []
                
                # Ensure verdict is one of the allowed values
                if result["verdict"] not in ["SAFE", "SUSPICIOUS", "MALICIOUS", "UNKNOWN"]:
                    result["verdict"] = "UNKNOWN"
                
                return result
            else:
                # Fallback if no JSON found
                return {
                    "verdict": "UNKNOWN",
                    "confidence": "Low",
                    "summary": response_text[:500],
                    "key_findings": ["Unable to parse Gemini response"],
                    "risk_factors": [],
                    "recommendations": ["Please try again or check API status"]
                }
                
        except json.JSONDecodeError:
            return {
                "verdict": "UNKNOWN",
                "confidence": "Low",
                "summary": "Unable to parse Gemini response as JSON",
                "key_findings": ["Response parsing error"],
                "risk_factors": [],
                "recommendations": ["Please try again or check API status"]
            }
            
    except Exception as e:
        error_msg = str(e)
        # Provide more helpful error messages
        if "404" in error_msg or "not found" in error_msg:
            return {
                "verdict": "UNKNOWN",
                "confidence": "Low",
                "summary": "Gemini model not available. Please check your API key and model configuration.",
                "key_findings": ["Model configuration error"],
                "risk_factors": [],
                "recommendations": [
                    "Verify your Gemini API key is correct",
                    "Try using 'gemini-1.5-pro' or 'gemini-1.0-pro' model",
                    "Check if Gemini API is enabled in your Google Cloud project"
                ]
            }
        else:
            return {
                "verdict": "UNKNOWN",
                "confidence": "Low",
                "summary": f"Gemini analysis failed: {error_msg[:200]}",
                "key_findings": ["Analysis error"],
                "risk_factors": [],
                "recommendations": ["Please try again or check API configuration"]
            }


# ============================================================================
# 6. UI/Results Helpers
# ============================================================================

def get_verdict_color(verdict: str) -> str:
    """Return color for the verdict."""
    colors = {
        "SAFE": "🟢",
        "SUSPICIOUS": "🟡",
        "MALICIOUS": "🔴",
        "UNKNOWN": "⚪"
    }
    return colors.get(verdict, "⚪")


def display_source_results(source_results: List[Dict[str, Any]]):
    """Display source results in expandable sections."""
    
    with st.expander("🔍 Source Intelligence", expanded=False):
        for result in source_results:
            source_name = result.get("source", "Unknown Source")
            status = result.get("status", "unknown")
            
            if status == "success":
                with st.expander(f"✅ {source_name}", expanded=False):
                    data = result.get("data", {})
                    # Display the data in a readable format
                    st.json(data)
            else:
                with st.expander(f"⚠️ {source_name} (Error)", expanded=False):
                    error_msg = result.get("error", "Unknown error")
                    st.warning(f"❌ {error_msg}")


def display_verdict_card(verdict_result: Dict[str, Any]):
    """Display the verdict card with color coding."""
    verdict = verdict_result.get("verdict", "UNKNOWN")
    confidence = verdict_result.get("confidence", "Medium")
    summary = verdict_result.get("summary", "No summary available")
    key_findings = verdict_result.get("key_findings", [])
    risk_factors = verdict_result.get("risk_factors", [])
    recommendations = verdict_result.get("recommendations", [])
    
    color_icon = get_verdict_color(verdict)
    
    # Determine background color based on verdict
    bg_colors = {
        "SAFE": "#d4edda",
        "SUSPICIOUS": "#fff3cd",
        "MALICIOUS": "#f8d7da",
        "UNKNOWN": "#e9ecef"
    }
    bg_color = bg_colors.get(verdict, "#f8f9fa")
    
    border_colors = {
        "SAFE": "#28a745",
        "SUSPICIOUS": "#ffc107",
        "MALICIOUS": "#dc3545",
        "UNKNOWN": "#6c757d"
    }
    border_color = border_colors.get(verdict, "#6c757d")
    
    # Use HTML for better visual styling
    st.markdown(f"""
    <div style="border: 3px solid {border_color}; border-radius: 10px; padding: 20px; margin: 10px 0;
                background-color: {bg_color};">
        <h2 style="margin: 0;">{color_icon} {verdict}</h2>
        <p style="margin: 5px 0;"><strong>Confidence:</strong> {confidence}</p>
        <p style="margin: 10px 0;"><strong>Summary:</strong> {summary}</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Display findings, risk factors, and recommendations
    if key_findings:
        st.markdown("### 📋 Key Findings")
        for finding in key_findings:
            st.markdown(f"- {finding}")
    
    if risk_factors:
        st.markdown("### ⚠️ Risk Factors")
        for risk in risk_factors:
            st.markdown(f"- {risk}")
    
    if recommendations:
        st.markdown("### 💡 Recommendations")
        for rec in recommendations:
            st.markdown(f"- {rec}")


# ============================================================================
# 7. Main App
# ============================================================================

def main():
    """Main application entry point."""
    
    # Title and description
    st.markdown("# 🛡️ ThreatLens")
    st.markdown("*IP, Domain & URL Security Intelligence Analyzer*")
    
    # Check for API keys
    missing_keys = check_api_keys()
    if missing_keys:
        if "STREAMLIT_SECRETS" in missing_keys:
            st.error("❌ Streamlit secrets not configured. Please set up secrets in Streamlit Cloud dashboard.")
        else:
            st.warning(f"⚠️ Missing API keys: {', '.join(missing_keys)}. Please add them to Streamlit Cloud secrets.")
        st.info("📝 **How to fix:**\n\n"
                "1. Go to your app on Streamlit Cloud\n"
                "2. Click on Settings (⚙️)\n"
                "3. In the Secrets section, add:\n\n"
                "```toml\n"
                "VIRUSTOTAL_API_KEY = \"your_key_here\"\n"
                "GEMINI_API_KEY = \"your_key_here\"\n"
                "```\n"
                "4. Click Save and redeploy your app")
        st.stop()
    
    # Input form
    with st.form(key="analysis_form"):
        col1, col2 = st.columns(2)
        
        with col1:
            target_type = st.selectbox(
                "Target Type",
                options=["Domain", "IP Address", "URL"],
                help="Select the type of target to analyze"
            )
        
        with col2:
            knowledge_level = st.selectbox(
                "Knowledge Level",
                options=["Beginner", "Intermediate", "Expert"],
                help="Select your technical level for response detail"
            )
        
        # Map selectbox values to internal types
        type_mapping = {
            "Domain": "Domain",
            "IP Address": "IP",
            "URL": "URL"
        }
        internal_type = type_mapping[target_type]
        
        target = st.text_input(
            "Target",
            placeholder=f"Enter {target_type.lower()}",
            help=f"Enter the {target_type.lower()} to analyze"
        )
        
        analyze_button = st.form_submit_button("🔍 Analyze", use_container_width=True)
        
    # Validation and analysis
    if analyze_button:
        if not target:
            st.error("Please enter a target to analyze")
            return
        
        target = target.strip()
        is_valid = False
        
        # Validate based on selected type
        if internal_type == "IP":
            is_valid = validate_ip(target)
        elif internal_type == "Domain":
            is_valid = validate_domain(target)
        elif internal_type == "URL":
            is_valid = validate_url(target)
        
        if not is_valid:
            st.error(f"Invalid {internal_type} format. Please check your input.")
            return
        
        # Show progress
        with st.spinner(f"Analyzing {target}..."):
            # Query all sources
            source_results = []
            progress_bar = st.progress(0)
            
            for idx, (source_name, source_func) in enumerate(SOURCES.items()):
                # Update progress
                progress_bar.progress((idx + 1) / len(SOURCES))
                
                try:
                    result = source_func(target, internal_type)
                    source_results.append(result)
                except Exception as e:
                    source_results.append({
                        "source": source_name,
                        "status": "error",
                        "data": {},
                        "error": f"Unexpected error in {source_name}: {str(e)}"
                    })
            
            progress_bar.empty()
            
            # Analyze with Gemini
            with st.spinner("Generating AI assessment..."):
                gemini_result = analyze_with_gemini(
                    target, internal_type, knowledge_level, source_results
                )
            
            # Display results
            col_left, col_right = st.columns([3, 1])
            with col_left:
                display_verdict_card(gemini_result)
            
            with col_right:
                st.metric("Target", target[:30] + "..." if len(target) > 30 else target)
                st.metric("Type", target_type)
                st.metric("Level", knowledge_level)
            
            # Display source results
            display_source_results(source_results)
            
            # Display raw data in an expander
            with st.expander("📊 Raw Data", expanded=False):
                st.json({
                    "target": target,
                    "target_type": internal_type,
                    "knowledge_level": knowledge_level,
                    "gemini_analysis": gemini_result,
                    "source_results": source_results
                })


if __name__ == "__main__":
    main()
