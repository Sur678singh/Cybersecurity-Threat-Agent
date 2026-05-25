# 🛡️ AI Cybersecurity SOC Agent

An AI-powered Cybersecurity SOC (Security Operations Center) Agent built using **LangGraph**, **LangChain**, **FastAPI**, and **LLMs** to automatically analyze security logs, detect cyber threats, map attacks to MITRE ATT&CK techniques, fetch CVE intelligence, and generate professional incident reports.

---

# 🚀 Features

- 🔍 Security Log Parsing
- ⚠️ Threat Detection Engine
- 🧠 AI-Powered Incident Report Generation
- 🛡️ MITRE ATT&CK Mapping
- 🌐 Threat Intelligence using AbuseIPDB
- 🧬 CVE Vulnerability Lookup
- 📊 Risk Scoring System
- 📄 Professional SOC Reports
- 💡 Security Recommendations
- ⚡ FastAPI Backend
- 🎨 Modern Cybersecurity Dashboard UI

---

# 🧠 Tech Stack

## Backend
- Python
- FastAPI
- LangChain
- LangGraph
- Groq LLM API
- Requests

## Frontend
- HTML
- CSS
- JavaScript

## APIs Used
- AbuseIPDB API
- NVD CVE API
- Groq API

---

# 📂 Project Structure

```bash
AI-Cybersecurity-SOC-Agent/
│
├── main.py  
├── requirements.txt
├──  .env
├── .gitignore
├── public/
│   ├── index.html
│   ├── style.css
│   └── script.js
├── requirements.txt
└── README.md
```

## 📦 Installation & Setup

### 1️⃣ Clone the repository

```bash
git clone https://github.com/your-username/AI-Cybersecurity-SOC-Agent.git
cd AI-Cybersecurity-SOC-Agent
```

---

### 2️⃣ Install dependencies

```bash
pip install -r requirements.txt
```

---

### 3️⃣ Setup environment variables

Create a `.env` file:

```
GROQ_API_KEY=your_api_key
ABUSEIPDB_API_KEY=your_api_key
```

---

### 4️⃣ Run the backend server

```bash
uvicorn AISocAgent:app --reload    # Used your app.py name
```

Server will run at:

```
http://127.0.0.1:8000
```

---

### 5️⃣ Run frontend

Just open:

```
index.html
```

OR use Live Server (recommended)

---

## 🔌 API Endpoints

### ▶️ Start Interview

**POST** `/Threat`

```json
{
  "query": "Failed login from 192.168.1.1"
}
```

## 🧪 Example Flow

1. SQL Injection Attack
2. Brute Force Attack
3. Malware Download
4. XSS Attack
5. Suspicious IP Activity

---

## 🧩 Key Components

START
  ↓
Parse Logs
  ↓
Detect Threats
  ↓
MITRE Mapping
  ↓
Threat Intelligence
  ↓
CVE Lookup
  ↓
Risk Scoring
  ↓
AI Report Generation
  ↓
Recommendations
  ↓
END

---

## ⚠️ Challenges Solved

* Cybersecurity Dashboard UI
* Risk Level Indicators
* Threat Cards
* MITRE Tables
* CVE Display
* Threat Intelligence Tables
* Professional Incident Reports

---

## 🚀 Future Improvements

* VirusTotal Integration
* SIEM Integration
* Real-time Monitoring
* PDF Report Export
* AI Chat With Logs
* Multi-Agent Architecture
* Email Alerts
* Authentication System


## 👨‍💻 Author

**Suryansh Singh**

---

## ⭐ Contribute

Feel free to fork this repo and improve it!

---

## 📄 License

This project is open-source and available under the MIT License.

---

## 💡 Inspiration

Built to real CyberSecurity State environments and help candidates improve how to deal with cyber threats.

---