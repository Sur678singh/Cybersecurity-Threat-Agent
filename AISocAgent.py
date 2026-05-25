from langchain_groq import ChatGroq
from langgraph.graph  import StateGraph,START,END
from typing import TypedDict,List
from pydantic import BaseModel
from dotenv import load_dotenv
import requests,re,os
from datetime import datetime
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse


# ********************************** Load Env And LLM ***************************************
load_dotenv()
# make llm
llm=ChatGroq(model='llama-3.1-8b-instant')

# ********************************** FastAPI Server *****************************************
app=FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

# *********************************Serve Frontend UI****************************
app.mount("/public",StaticFiles(directory='public'),name='public')
# get request from server
@app.get("/")
def serve_frontend():
    return FileResponse("public/index.html")

# ********************************* STATE ***************************************************
class SOCState(TypedDict):
    logs:str
    parsed_logs:List[str]
    threats:List[str]
    risk_score:str
    report:str
    recommendations:str
    mitre_data:List[dict]
    threat_intel:List[dict]
    cve_data:List[dict]

# for prompt
MITRE_MAPPINGS = {

    "Possible Brute Force Attack": {
        "id": "T1110",
        "technique": "Brute Force"
    },

    "Possible SQL Injection Attack": {
        "id": "T1190",
        "technique": "Exploit Public-Facing Application"
    },

    "Possible XSS Attack": {
        "id": "T1059",
        "technique": "Command and Scripting Interpreter"
    },

    "Possible Malware Download": {
        "id": "T1105",
        "technique": "Ingress Tool Transfer"
    }
}

# threats score
THREAT_SCORES = {
    "Possible SQL Injection Attack": 5,
    "Possible Brute Force Attack": 4,
    "Possible XSS Attack": 3,
    'Possible Malware Download': 5
}

# ********************************* Functions Graph ***************************************
def parse_logs(state:SOCState):
    logs=state['logs']
    lines=logs.split("\n")
    parsed=[]
    for line in lines:
        line=line.strip()
        if line:
            parsed.append(line)
    return {'parsed_logs':parsed}

# threats detector
def detect_threats(state:SOCState):
    parsed_logs=state['parsed_logs']
    threats=[]
    failed_login_count=0

    SQL_PATTERNS = [
        r"select\s+\*\s+from",
        r"union\s+select",
        r"or\s+1=1",
        r"drop\s+table",
        r"--",
        r"insert\s+into",
   ]

    XSS_PATTERNS = [
        r"<script>",
        r"javascript:",
        r"onerror=",
        r"alert\(",
    ]

    BRUTE_FORCE_PATTERNS = [
        r"failed login",
        r"invalid password",
        r"authentication failed",
    ]

    MALWARE_PATTERNS = [
    r"malware",
    r"payload\.exe",
    r"encryptor\.exe",
    r"ransomware",
    r"shadow copies deleted",
    r"vssadmin",
    r"suspicious outbound connection",
    r"trojan",
    r"beaconing",
    r"encryption activity"
]

    for log in parsed_logs:
        lower_log = log.lower().strip()
        for pattern in BRUTE_FORCE_PATTERNS:
            if re.search(pattern, lower_log):
                failed_login_count += 1

        for pattern in SQL_PATTERNS:
            if re.search(pattern, lower_log):
                threats.append('Possible SQL Injection Attack')
        
        for pattern in XSS_PATTERNS:
            if re.search(pattern, lower_log):
                threats.append('Possible XSS Injection Attack')
        
        for pattern in MALWARE_PATTERNS:
           if re.search(pattern, lower_log):
            threats.append('Possible Malware Download')
        
    if failed_login_count>=3:
        threats.append('Possible Brute Force Attack')
        
    threats = list(set(threats))
    if not threats:
        threats.append('No Major threats Detected')

    return {'threats':threats}

# function for mitre attack
def mitre_mapper(state: SOCState):
    threats = state["threats"]
    mitre_results = []
    for threat in threats:
        if threat in MITRE_MAPPINGS:
            mitre_results.append({
                "threat": threat,
                "mitre_id": MITRE_MAPPINGS[threat]["id"],
                "technique": MITRE_MAPPINGS[threat]["technique"]
            })

    return {"mitre_data": mitre_results}

# function for 
def threat_intelligence(state: SOCState):
    logs = state["logs"]
    ips = re.findall(r'(?:\d{1,3}\.){3}\d{1,3}', logs)
    threat_data = []
    for ip in ips:

        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {
                "Key": os.getenv("ABUSEIPDB_API_KEY"),
                "Accept": "application/json"
            }
            params = {
                "ipAddress": ip
            }
            response = requests.get(url,headers=headers,params=params)
            data = response.json()
            if "data" in data:
                threat_data.append({
                    "ip": ip,
                    "abuse_score": data["data"]["abuseConfidenceScore"],
                    "country": data["data"]["countryCode"]
                })

        except Exception as e:
            print(f"Threat Intel Error: {e}")

    return {
        "threat_intel": threat_data
    }

# function for cve
def cve_lookup(state: SOCState):
    threats = state["threats"]
    cve_results = []
    for threat in threats:
        try:
            keyword = ""

            if "SQL Injection" in threat:
                keyword = "SQL Injection"

            elif "Brute Force" in threat:
                keyword = "Authentication"

            elif "XSS" in threat:
                keyword = "Cross Site Scripting"

            elif "Malware" in threat:
                keyword = "Cross Site Scripting"

            if keyword:
                url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}"

                response = requests.get(url)

                data:dict = response.json()

                vulnerabilities = data.get("vulnerabilities", [])[:3]

                for item in vulnerabilities:
                    item:dict=item
                    cve:dict = item.get("cve", {})
                    cve_results.append({"id": cve.get("id"),
                        "description": cve.get("descriptions",[{}])[0].get("value", "")[:150]
                    })
        except Exception as e:
            print(f"CVE Error: {e}")

    return {
        "cve_data": cve_results
    }

# function for risk scoring
def calculate_risk(state:SOCState):
    threats=state['threats']
    score=0
    for threat in threats:
        score += THREAT_SCORES.get(threat, 0)

    if score >= 8:
        level='Critical'
    elif score >=5:
        level='High'
    elif score >=3:
        level='Medium'
    else:
        level='Low'

    risk=f"{level} Risk ({score}/10)" 
    return {'risk_score':risk}

# function for report
def generate_report(state:SOCState):
    current_time = datetime.now()
    date = current_time.strftime("%Y-%m-%d")
    time = current_time.strftime("%H:%M:%S")
    # prompt
    prompt=f"""You are a CyberSecurity SOC Analyst.
    Current Date: {date}
    Current Time: {time}
    Logs:
    {state["logs"]}

    Threats:
    {state["threats"]}

    MITRE:
    {state["mitre_data"]}

    Threat Intel:
    {state["threat_intel"]}

    CVE Data:
    {state["cve_data"]}

    Risk:
    {state["risk_score"]}

    Create a professional cybersecurity incident report with:

    1. Incident Summary
    2. Attack Explanation
    3. MITRE ATT&CK Mapping
    4. Threat Intelligence Analysis
    5. Vulnerability Analysis
    6. Impact
    7. Recommendations
"""
    response=llm.invoke(prompt).content
    return {'report':response}

# function for recommendation
def recommendations_fix(state:SOCState):
    prompt=f"""You Are a CyberSecurity Expert.

    Based on these threats:{state['threats']}

    Give Security Recommendation for prevents Attack.
"""
    res=llm.invoke(prompt).content
    return {'recommendations':res}

# ******************************** Graph Making *********************************************
graph=StateGraph(SOCState)
# graph add
graph.add_node('parse_logs', parse_logs)
graph.add_node('detect_threats', detect_threats)
graph.add_node('calculate_risk', calculate_risk)
graph.add_node('generate_report', generate_report)
graph.add_node('recommendations', recommendations_fix)
graph.add_node('mitre_mapper', mitre_mapper)
graph.add_node('cve_lookup', cve_lookup)
graph.add_node('threat_intelligence', threat_intelligence)
# add edges 
graph.add_edge(START,'parse_logs')
graph.add_edge('parse_logs', 'detect_threats')
graph.add_edge('detect_threats', 'mitre_mapper')
graph.add_edge('mitre_mapper','threat_intelligence')
graph.add_edge('threat_intelligence','cve_lookup')
graph.add_edge('cve_lookup','calculate_risk')
graph.add_edge('calculate_risk','generate_report')
graph.add_edge('generate_report','recommendations')
graph.add_edge('recommendations',END)

Agent=graph.compile()

# **************************************** Connect API *********************************
class QueryState(BaseModel):
    query:str

# connect fastapi
@app.post("/Threat")
def threats(q:QueryState):
    result=Agent.invoke({'logs':q.query})
    return {
        "parsed_logs": result.get("parsed_logs", []),
        "threats": result.get("threats", []),
        "risk_score": result.get("risk_score", ""),
        "mitre_data": result.get("mitre_data", []),
        "threat_intel": result.get("threat_intel", []),
        "cve_data": result.get("cve_data", []),
        "report": result.get("report", ""),
        "recommendations": result.get("recommendations", "")
    }
