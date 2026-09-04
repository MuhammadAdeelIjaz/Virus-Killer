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

st.set_page_config(
    page_title="ThreatLens",
    page_icon="🛡️",
    layout="centered"
)

def check_api_keys():
    missing_keys = []
    if not hasattr(st, 'secrets') or not st.secrets:
        return ["STREAMLIT_SECRETS"]
    if "VIRUSTOTAL_API_KEY" not in st.secrets or not st.secrets["VIRUSTOTAL_API_KEY"]:
        missing_keys.append("VIRUSTOTAL_API_KEY")
    if "GEMINI_API_KEY" not in st.secrets or not st.secrets["GEMINI_API_KEY"]:
        missing_keys.append("GEMINI_API_KEY")
    if "ABUSEIPDB_API_KEY" not in st.secrets or not st.secrets["ABUSEIPDB_API_KEY"]:
        missing_keys.append("ABUSEIPDB_API_KEY")
    if "GOOGLE_SAFE_BROWSING_API_KEY" not in st.secrets or not st.secrets["GOOGLE_SAFE_BROWSING_API_KEY"]:
        missing_keys.append("GOOGLE_SAFE_BROWSING_API_KEY")
    if "URLSCAN_API_KEY" not in st.secrets or not st.secrets["URLSCAN_API_KEY"]:
        missing_keys.append("URLSCAN_API_KEY")
    return missing_keys

# ============================================================================
# 2. Validation Helpers
# ============================================================================

def validate_ip(ip_str: str) -> bool:
    try:
        ipaddress.ip_address(ip_str.strip())
        return True
    except ValueError:
        return False

def validate_domain(domain_str: str) -> bool:
    domain_str = domain_str.strip().lower()
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain_str))

def validate_url(url_str: str) -> bool:
    url_str = url_str.strip()
    try:
        parsed = urlparse(url_str)
        if not parsed.scheme or not parsed.netloc:
            return False
        if parsed.scheme not in ['http', 'https']:
            return False
        domain = parsed.netloc.split(':')[0]
        return validate_domain(domain) or validate_ip(domain)
    except Exception:
        return False

def extract_domain_from_url(url_str: str) -> Optional[str]:
    try:
        parsed = urlparse(url_str.strip())
        domain = parsed.netloc.split(':')[0]
        return domain if domain else None
    except Exception:
        return None

# ============================================================================
# 3. Source Functions
# ============================================================================

def get_virustotal(target: str, target_type: str) -> Dict[str, Any]:
    api_key = st.secrets.get("VIRUSTOTAL_API_KEY")
    if not api_key:
        return {"source": "VirusTotal", "status": "error", "data": {}, "error": "VirusTotal API key not configured"}
    
    base_url = "https://www.virustotal.com/api/v3"
    endpoint = ""
    encoded_target = target.strip()
    
    if target_type == "IP":
        endpoint = f"/ip_addresses/{encoded_target}"
    elif target_type == "Domain":
        endpoint = f"/domains/{encoded_target}"
    elif target_type == "URL":
        import base64
        url_bytes = encoded_target.encode('utf-8')
        url_id = base64.urlsafe_b64encode(url_bytes).decode('utf-8').rstrip('=')
        endpoint = f"/urls/{url_id}"
    else:
        return {"source": "VirusTotal", "status": "error", "data": {}, "error": f"Unsupported target type: {target_type}"}
    
    headers = {"x-apikey": api_key, "Accept": "application/json"}
    
    try:
        response = requests.get(f"{base_url}{endpoint}", headers=headers, timeout=30)
        if response.status_code == 404:
            return {"source": "VirusTotal", "status": "error", "data": {}, "error": "Target not found in VirusTotal database"}
        elif response.status_code == 429:
            return {"source": "VirusTotal", "status": "error", "data": {}, "error": "Rate limit exceeded. Please try again later."}
        elif response.status_code != 200:
            return {"source": "VirusTotal", "status": "error", "data": {}, "error": f"HTTP Error {response.status_code}"}
        
        data = response.json()
        result = {"source": "VirusTotal", "status": "success", "data": {}, "error": None}
        
        if "data" in data:
            attributes = data["data"].get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            result["data"]["stats"] = {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "timeout": stats.get("timeout", 0)
            }
            result["data"]["reputation"] = attributes.get("reputation", 0)
            
            if target_type == "IP":
                result["data"]["country"] = attributes.get("country", None)
                result["data"]["as_owner"] = attributes.get("as_owner", None)
                result["data"]["asn"] = attributes.get("asn", None)
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
            
            results = attributes.get("last_analysis_results", {})
            vendor_detections = []
            for vendor, detection in results.items():
                if detection.get("category") in ["malicious", "suspicious"]:
                    vendor_detections.append({"vendor": vendor, "category": detection.get("category"), "result": detection.get("result", "Unknown")})
            result["data"]["vendor_detections"] = vendor_detections[:10]
        else:
            result["status"] = "error"
            result["error"] = "Unexpected API response format"
        
        return result
    except Exception as e:
        return {"source": "VirusTotal", "status": "error", "data": {}, "error": f"Unexpected error: {str(e)}"}


def get_whois(target: str, target_type: str) -> Dict[str, Any]:
    try:
        if target_type == "URL":
            domain = extract_domain_from_url(target)
            if not domain:
                return {"source": "WHOIS", "status": "error", "data": {}, "error": "Could not extract domain from URL"}
        elif target_type == "IP":
            domain = target
        else:
            domain = target.strip()
        
        try:
            w = whois.whois(domain, timeout=10)
        except whois.parser.PywhoisError as e:
            return {"source": "WHOIS", "status": "error", "data": {}, "error": f"WHOIS lookup failed: {str(e)[:200]}"}
        
        if not w or not w.domain_name:
            return {"source": "WHOIS", "status": "error", "data": {}, "error": "No WHOIS data available"}
        
        result = {"source": "WHOIS", "status": "success", "data": {}, "error": None}
        
        # HELPER TO CONVERT DATETIME OBJECTS TO STRINGS
        def clean_date(val):
            if isinstance(val, list):
                return [str(v) for v in val]
            return str(val) if val else "N/A"

        result["data"]["domain_name"] = str(w.domain_name) if w.domain_name else "N/A"
        result["data"]["registrar"] = str(w.registrar) if w.registrar else "N/A"
        result["data"]["creation_date"] = clean_date(w.creation_date)
        result["data"]["expiration_date"] = clean_date(w.expiration_date)
        result["data"]["updated_date"] = clean_date(w.updated_date)
        
        if w.name_servers:
            result["data"]["name_servers"] = [str(ns) for ns in w.name_servers] if isinstance(w.name_servers, list) else [str(w.name_servers)]
        else:
            result["data"]["name_servers"] = []
        
        result["data"]["org"] = str(w.org) if w.org else "N/A"
        result["data"]["country"] = str(w.country) if w.country else "N/A"
        
        if w.status:
            result["data"]["status"] = [str(s) for s in w.status] if isinstance(w.status, list) else [str(w.status)]
        else:
            result["data"]["status"] = []
        
        if w.emails:
            result["data"]["emails"] = [str(e) for e in w.emails] if isinstance(w.emails, list) else [str(w.emails)]
        else:
            result["data"]["emails"] = []
        
        result["data"]["dnssec"] = str(w.dnssec) if w.dnssec else "N/A"
        
        return result
    except Exception as e:
        return {"source": "WHOIS", "status": "error", "data": {}, "error": f"Unexpected WHOIS error: {str(e)}"}


def get_abuseipdb(target: str, target_type: str) -> Dict[str, Any]:
    api_key = st.secrets.get("ABUSEIPDB_API_KEY")
    if target_type != "IP":
        return {"source": "AbuseIPDB", "status": "skipped", "data": {}, "error": "AbuseIPDB is only applicable for IP addresses"}
    if not api_key:
        return {"source": "AbuseIPDB", "status": "error", "data": {}, "error": "AbuseIPDB API key not configured"}

    url = 'https://api.abuseipdb.com/api/v2/check'
    querystring = {'ipAddress': target, 'maxAgeInDays': '90'}
    headers = {'Accept': 'application/json', 'Key': api_key}

    try:
        response = requests.request(method='GET', url=url, headers=headers, params=querystring, timeout=30)
        if response.status_code == 429:
            return {"source": "AbuseIPDB", "status": "error", "data": {}, "error": "Rate limit exceeded."}
        if response.status_code != 200:
            return {"source": "AbuseIPDB", "status": "error", "data": {}, "error": f"HTTP Error {response.status_code}"}

        data = response.json().get('data', {})
        return {
            "source": "AbuseIPDB", "status": "success", "error": None,
            "data": {
                "abuse_confidence_score": data.get('abuseConfidenceScore', 0),
                "country": data.get('countryCode', "N/A"),
                "usage_type": data.get('usageType', "N/A"),
                "isp": data.get('isp', "N/A"),
                "total_reports": data.get('totalReports', 0),
                "num_distinct_users": data.get('numDistinctUsers', 0)
            }
        }
    except Exception as e:
        return {"source": "AbuseIPDB", "status": "error", "data": {}, "error": str(e)}


def get_google_safe_browsing(target: str, target_type: str) -> Dict[str, Any]:
    api_key = st.secrets.get("GOOGLE_SAFE_BROWSING_API_KEY")
    if target_type not in ["URL", "Domain"]:
        return {"source": "Google Safe Browsing", "status": "skipped", "data": {}, "error": "Google Safe Browsing is only applicable for URLs and Domains"}
    if not api_key:
        return {"source": "Google Safe Browsing", "status": "error", "data": {}, "error": "Google Safe Browsing API key not configured"}

    url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    lookup_url = target
    if target_type == "Domain" and not target.startswith(('http://', 'https://')):
        lookup_url = f"http://{target}/"

    payload = {
        "client": {"clientId": "ThreatLens", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": lookup_url}]
        }
    }

    try:
        response = requests.post(url, json=payload, timeout=30)
        if response.status_code != 200:
            return {"source": "Google Safe Browsing", "status": "error", "data": {}, "error": f"HTTP Error {response.status_code}"}

        data = response.json()
        if "matches" not in data:
            return {"source": "Google Safe Browsing", "status": "success", "data": {"threat_found": False, "message": "No threats found in Google Safe Browsing database."}, "error": None}
        
        threats = data["matches"]
        threat_types = [t.get("threatType", "UNKNOWN") for t in threats]
        return {"source": "Google Safe Browsing", "status": "success", "data": {"threat_found": True, "threat_types": threat_types, "message": f"Threat detected! Types: {', '.join(threat_types)}"}, "error": None}
        
    except Exception as e:
        return {"source": "Google Safe Browsing", "status": "error", "data": {}, "error": str(e)}


# UPDATED URLSCAN TO FIX THE MISMATCH
def get_urlscan(target: str, target_type: str) -> Dict[str, Any]:
    api_key = st.secrets.get("URLSCAN_API_KEY")
    if target_type not in ["URL", "Domain"]:
        return {"source": "URLScan.io", "status": "skipped", "data": {}, "error": "URLScan.io is only applicable for URLs and Domains"}
    if not api_key:
        return {"source": "URLScan.io", "status": "error", "data": {}, "error": "URLScan.io API key not configured"}

    domain = target
    if target_type == "URL":
        domain = extract_domain_from_url(target)
        if not domain:
            return {"source": "URLScan.io", "status": "error", "data": {}, "error": "Could not extract domain"}

    # Use exact domain matching to avoid picking up unrelated scans
    search_url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=1"
    headers = {"API-Key": api_key}

    try:
        response = requests.get(search_url, headers=headers, timeout=30)
        if response.status_code != 200:
            return {"source": "URLScan.io", "status": "error", "data": {}, "error": f"HTTP Error {response.status_code}"}

        data = response.json()
        results = data.get("results", [])
        
        if not results:
            return {"source": "URLScan.io", "status": "success", "data": {"scan_found": False, "message": "No prior scans found for this domain in URLScan.io."}, "error": None}

        # Filter to ensure the exact domain matches the search
        valid_result = None
        for r in results:
            try:
                url_domain = urlparse(r.get("page", {}).get("url", "")).netloc
                if domain in url_domain:
                    valid_result = r
                    break
            except:
                continue
        
        if not valid_result:
            return {"source": "URLScan.io", "status": "success", "data": {"scan_found": False, "message": "No exact domain match found in recent scans."}, "error": None}

        latest = valid_result
        return {
            "source": "URLScan.io", "status": "success", "error": None,
            "data": {
                "scan_found": True,
                "scan_url": latest.get("page", {}).get("url", "N/A"),
                "screenshot_url": latest.get("task", {}).get("screenshotURL", "No screenshot available"),
                "score": latest.get("stats", {}).get("score", 0),
                "malicious": latest.get("stats", {}).get("malicious", 0),
                "country": latest.get("page", {}).get("country", "N/A"),
                "server": latest.get("page", {}).get("server", "N/A")
            }
        }
    except Exception as e:
        return {"source": "URLScan.io", "status": "error", "data": {}, "error": str(e)}

# ============================================================================
# 4. SOURCES Registry
# ============================================================================

SOURCES = {
    "VirusTotal": get_virustotal,
    "AbuseIPDB": get_abuseipdb,
    "Google Safe Browsing": get_google_safe_browsing,
    "URLScan.io": get_urlscan,
    "WHOIS": get_whois,
}

# ============================================================================
# 5. Gemini Analysis
# ============================================================================

def build_gemini_prompt(target: str, target_type: str, knowledge_level: str, source_results: List[Dict[str, Any]]) -> str:
    source_data_str = json.dumps(source_results, indent=2)
    
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
    
    if knowledge_level == "Beginner":
        prompt = f"{base_instruction}\nUse very simple, clear language.\nTarget: {target}\nKnowledge Level: Beginner\nSource Data:\n{source_data_str}"
    elif knowledge_level == "Intermediate":
        prompt = f"{base_instruction}\nProvide a balanced technical assessment.\nTarget: {target}\nKnowledge Level: Intermediate\nSource Data:\n{source_data_str}"
    else:
        prompt = f"{base_instruction}\nProvide a concise technical assessment.\nTarget: {target}\nKnowledge Level: Expert\nSource Data:\n{source_data_str}"
    
    return prompt


def analyze_with_gemini(target: str, target_type: str, knowledge_level: str, source_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    api_key = st.secrets.get("GEMINI_API_KEY")
    if not api_key:
        return {"verdict": "UNKNOWN", "confidence": "Low", "summary": "Gemini API key not configured", "key_findings": ["API configuration error"], "risk_factors": [], "recommendations": ["Please configure Gemini API key in Streamlit Cloud settings"]}
    
    try:
        genai.configure(api_key=api_key)
        model_name = "gemini-3.6-flash"
        
        try:
            model = genai.GenerativeModel(model_name)
        except Exception as e:
            return {"verdict": "UNKNOWN", "confidence": "Low", "summary": f"Could not initialize Gemini model {model_name}. Error: {str(e)[:200]}", "key_findings": ["Model initialization failed"], "risk_factors": [], "recommendations": ["Check your Gemini API key is valid"]}
        
        prompt = build_gemini_prompt(target, target_type, knowledge_level, source_results)
        
        try:
            response = model.generate_content(prompt, generation_config={"temperature": 0.1, "top_p": 0.95, "top_k": 40, "max_output_tokens": 8192})
        except TypeError:
            response = model.generate_content(prompt)
        
        response_text = response.text.strip()
        
        try:
            json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
            if json_match:
                json_str = json_match.group()
                result = json.loads(json_str)
                result.setdefault("verdict", "UNKNOWN")
                result.setdefault("confidence", "Medium")
                result.setdefault("summary", "Analysis completed")
                result.setdefault("key_findings", [])
                result.setdefault("risk_factors", [])
                result.setdefault("recommendations", [])
                
                if result["verdict"] not in ["SAFE", "SUSPICIOUS", "MALICIOUS", "UNKNOWN"]:
                    result["verdict"] = "UNKNOWN"
                
                return result
            else:
                return {"verdict": "UNKNOWN", "confidence": "Low", "summary": "Could not parse Gemini response as JSON", "key_findings": ["Parsing error"], "risk_factors": [], "recommendations": ["Please try again"]}
        except json.JSONDecodeError:
            return {"verdict": "UNKNOWN", "confidence": "Low", "summary": "Invalid JSON in Gemini response", "key_findings": ["JSON parsing error"], "risk_factors": [], "recommendations": ["Please try again"]}
            
    except Exception as e:
        error_msg = str(e)
        return {"verdict": "UNKNOWN", "confidence": "Low", "summary": f"Gemini analysis failed: {error_msg[:200]}", "key_findings": ["Analysis error"], "risk_factors": [], "recommendations": ["Please try again or check API configuration"]}

# ============================================================================
# 6. UI/Results Helpers
# ============================================================================

def get_verdict_color(verdict: str) -> str:
    colors = {"SAFE": "🟢", "SUSPICIOUS": "🟡", "MALICIOUS": "🔴", "UNKNOWN": "⚪"}
    return colors.get(verdict, "⚪")

def display_source_results(source_results: List[Dict[str, Any]]):
    with st.expander("🔍 Source Intelligence", expanded=False):
        for result in source_results:
            source_name = result.get("source", "Unknown Source")
            status = result.get("status", "unknown")
            
            if status == "success":
                with st.expander(f"✅ {source_name}", expanded=False):
                    st.json(result.get("data", {}))
            elif status == "skipped":
                with st.expander(f"⏭️ {source_name}", expanded=False):
                    st.info(result.get("error", "Source skipped for this target type."))
            else:
                with st.expander(f"⚠️ {source_name} (Error)", expanded=False):
                    st.warning(f"❌ {result.get('error', 'Unknown error')}")

def display_verdict_card(verdict_result: Dict[str, Any]):
    verdict = verdict_result.get("verdict", "UNKNOWN")
    confidence = verdict_result.get("confidence", "Medium")
    summary = verdict_result.get("summary", "No summary available")
    key_findings = verdict_result.get("key_findings", [])
    risk_factors = verdict_result.get("risk_factors", [])
    recommendations = verdict_result.get("recommendations", [])
    
    color_icon = get_verdict_color(verdict)
    bg_colors = {"SAFE": "#d4edda", "SUSPICIOUS": "#fff3cd", "MALICIOUS": "#f8d7da", "UNKNOWN": "#e9ecef"}
    bg_color = bg_colors.get(verdict, "#f8f9fa")
    border_colors = {"SAFE": "#28a745", "SUSPICIOUS": "#ffc107", "MALICIOUS": "#dc3545", "UNKNOWN": "#6c757d"}
    border_color = border_colors.get(verdict, "#6c757d")
    
    st.markdown(f"""
    <div style="border: 3px solid {border_color}; border-radius: 10px; padding: 20px; margin: 10px 0; background-color: {bg_color};">
        <h2 style="margin: 0;">{color_icon} {verdict}</h2>
        <p style="margin: 5px 0;"><strong>Confidence:</strong> {confidence}</p>
        <p style="margin: 10px 0;"><strong>Summary:</strong> {summary}</p>
    </div>
    """, unsafe_allow_html=True)
    
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
    st.markdown("# 🛡️ ThreatLens")
    st.markdown("*IP, Domain & URL Security Intelligence Analyzer*")
    
    missing_keys = check_api_keys()
    if missing_keys:
        if "STREAMLIT_SECRETS" in missing_keys:
            st.error("❌ Streamlit secrets not configured. Please set up secrets in Streamlit Cloud dashboard.")
        else:
            st.warning(f"⚠️ Missing API keys: {', '.join(missing_keys)}")
        st.info("📝 **How to fix:**\n\n1. Go to your app on Streamlit Cloud\n2. Click on Settings (⚙️)\n3. In the Secrets section, add:\n\n```toml\nVIRUSTOTAL_API_KEY = \"your_key_here\"\nGEMINI_API_KEY = \"your_key_here\"\nABUSEIPDB_API_KEY = \"your_key_here\"\nGOOGLE_SAFE_BROWSING_API_KEY = \"your_key_here\"\nURLSCAN_API_KEY = \"your_key_here\"\n```\n4. Click Save and redeploy your app")
        st.stop()
    
    with st.form(key="analysis_form"):
        col1, col2 = st.columns(2)
        with col1:
            target_type = st.selectbox("Target Type", options=["Domain", "IP Address", "URL"])
        with col2:
            knowledge_level = st.selectbox("Knowledge Level", options=["Beginner", "Intermediate", "Expert"])
        
        type_mapping = {"Domain": "Domain", "IP Address": "IP", "URL": "URL"}
        internal_type = type_mapping[target_type]
        
        target = st.text_input("Target", placeholder=f"Enter {target_type.lower()}")
        analyze_button = st.form_submit_button("🔍 Analyze", use_container_width=True)
        
    if analyze_button:
        if not target:
            st.error("Please enter a target to analyze")
            return
        
        target = target.strip()
        is_valid = False
        if internal_type == "IP":
            is_valid = validate_ip(target)
        elif internal_type == "Domain":
            is_valid = validate_domain(target)
        elif internal_type == "URL":
            is_valid = validate_url(target)
        
        if not is_valid:
            st.error(f"Invalid {internal_type} format. Please check your input.")
            return
        
        with st.spinner(f"Analyzing {target}..."):
            source_results = []
            progress_bar = st.progress(0)
            total_sources = len(SOURCES)
            
            for idx, (source_name, source_func) in enumerate(SOURCES.items()):
                progress_bar.progress((idx + 1) / total_sources)
                try:
                    result = source_func(target, internal_type)
                    source_results.append(result)
                    time.sleep(1) 
                except Exception as e:
                    source_results.append({"source": source_name, "status": "error", "data": {}, "error": f"Unexpected error: {str(e)}"})
            
            progress_bar.empty()
            
            with st.spinner("Generating AI assessment..."):
                gemini_result = analyze_with_gemini(target, internal_type, knowledge_level, source_results)
            
            col_left, col_right = st.columns([3, 1])
            with col_left:
                display_verdict_card(gemini_result)
            with col_right:
                st.metric("Target", target[:30] + "..." if len(target) > 30 else target)
                st.metric("Type", target_type)
                st.metric("Level", knowledge_level)
            
            display_source_results(source_results)
            
            with st.expander("📊 Raw Data", expanded=False):
                st.json({"target": target, "target_type": internal_type, "knowledge_level": knowledge_level, "gemini_analysis": gemini_result, "source_results": source_results})

if __name__ == "__main__":
    main()
