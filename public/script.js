// ======================================
// SAMPLE LOGS
// ======================================

const SAMPLE_LOGS = `
2024-01-15 10:23:45 [WARN] Failed login attempt from 192.168.1.100 user=admin
2024-01-15 10:23:47 [WARN] Failed login attempt from 192.168.1.100 user=admin
2024-01-15 10:23:49 [WARN] Failed login attempt from 192.168.1.100 user=root
2024-01-15 10:24:01 [ERROR] SQL injection attempt detected: ' OR '1'='1
2024-01-15 10:24:15 [CRITICAL] Suspicious outbound connection to 45.142.122.10:4444
2024-01-15 10:25:00 [WARN] Unusual file access: /etc/shadow by user www-data
`;

// ======================================
// BACKEND API
// ======================================

const API_URL ="http://localhost:8000";

// ======================================
// LOAD SAMPLE LOGS
// ======================================

function loadSample() {

  document
    .getElementById("logs")
    .value =
    SAMPLE_LOGS.trim();
}

// ======================================
// CLEAR ALL
// ======================================

function clearAll() {

  document
    .getElementById("logs")
    .value = "";

  document
    .getElementById("results")
    .classList.add("hidden");

  document
    .getElementById("error")
    .classList.add("hidden");
}

// ======================================
// SHOW ERROR
// ======================================

function showError(message) {

  const errorEl =
    document.getElementById("error");

  errorEl.textContent = message;

  errorEl.classList.remove("hidden");
}

// ======================================
// LOADING BUTTON
// ======================================

function setLoading(isLoading) {

  const btn =
    document.getElementById("analyzeBtn");

  if (isLoading) {

    btn.disabled = true;

    btn.innerHTML = `
      <span class="loading"></span>
      Analyzing...
    `;

  } else {

    btn.disabled = false;

    btn.textContent =
      "Analyze Threats";
  }
}

// ======================================
// ESCAPE HTML
// ======================================

function escapeHtml(text) {

  return String(text).replace(

    /[&<>"']/g,

    (char) => ({

      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;"

    })[char]
  );
}

// ======================================
// RISK COLOR CLASS
// ======================================

function getRiskClass(score) {

  const value =
    String(score).toLowerCase();

  if (
    value.includes("critical") ||
    value.includes("10") ||
    value.includes("9")
  ) {
    return "risk-critical";
  }

  if (
    value.includes("high") ||
    value.includes("8") ||
    value.includes("7")
  ) {
    return "risk-high";
  }

  if (
    value.includes("medium") ||
    value.includes("6") ||
    value.includes("5") ||
    value.includes("4")
  ) {
    return "risk-medium";
  }

  return "risk-low";
}

// ======================================
// DOWNLOAD REPORT
// ======================================

function downloadReport() {

  const report =
    document
      .getElementById("report")
      .innerText;

  const blob =
    new Blob(
      [report],
      { type: "text/plain" }
    );

  const link =
    document.createElement("a");

  link.href =
    URL.createObjectURL(blob);

  link.download =
    "incident_report.txt";

  link.click();
}

// ======================================
// FORMAT INCIDENT REPORT
// ======================================

function formatReport(report) {

  if (!report) {

    return `
      <p>No report generated</p>
    `;
  }

  let formatted = report;

  // ============================
  // HEADINGS
  // ============================

  formatted =
    formatted.replace(

      /\*\*(.*?)\*\*/g,

      '<h3>$1</h3>'
    );

  // ============================
  // BULLET POINTS
  // ============================

  formatted =
    formatted.replace(

      /^\d+\.\s(.+)$/gm,

      '<div class="report-point">$1</div>'
    );

  // ============================
  // TABLE STYLE
  // ============================

  formatted =
    formatted.replace(

      /\|(.+)\|/g,

      '<div class="table-line">$&</div>'
    );

  // ============================
  // LINE BREAKS
  // ============================

  formatted =
    formatted.replace(
      /\n/g,
      "<br>"
    );

  return formatted;
}

// ======================================
// FORMAT RECOMMENDATIONS
// ======================================

function formatRecommendations(text) {

  if (!text) {

    return `
      <p>No recommendations generated</p>
    `;
  }

  let formatted = text;

  // ============================
  // HEADINGS
  // ============================

  formatted =
    formatted.replace(

      /\*\*(.*?)\*\*/g,

      '<h3>$1</h3>'
    );

  // ============================
  // NUMBERED POINTS
  // ============================

  formatted =
    formatted.replace(

      /^\d+\.\s(.+)$/gm,

      '<div class="recommendation-point">$1</div>'
    );

  // ============================
  // BULLET POINTS
  // ============================

  formatted =
    formatted.replace(

      /^\*\s(.+)$/gm,

      '<div class="recommendation-bullet">• $1</div>'
    );

  // ============================
  // LINE BREAKS
  // ============================

  formatted =
    formatted.replace(
      /\n/g,
      "<br>"
    );

  return formatted;
}

// ======================================
// API REQUEST
// ======================================

async function analyzeThreats() {

  const logs =

    document
      .getElementById("logs")
      .value
      .trim();

  // ============================
  // VALIDATION
  // ============================

  if (!logs) {

    showError(
      "Please enter logs to analyze"
    );

    return;
  }

  document
    .getElementById("error")
    .classList.add("hidden");

  setLoading(true);

  const startTime =
    performance.now();

  try {

    const response =
      await fetch(
        `${API_URL}/Threat`,
        {

          method: "POST",

          headers: {
            "Content-Type":
              "application/json"
          },

          body: JSON.stringify({
            query: logs
          })
        }
      );

    // ============================
    // RESPONSE CHECK
    // ============================

    if (!response.ok) {

      throw new Error(
        `HTTP ${response.status}`
      );
    }

    const data =
      await response.json();

    renderResults(data);

    // ============================
    // ANALYSIS TIME
    // ============================

    const endTime =
      performance.now();

    document
      .getElementById("analysisTime")
      .textContent =

      `${(
        (endTime - startTime) / 1000
      ).toFixed(2)}s`;

  } catch (error) {

    console.error(error);

    showError(
      `Request failed: ${error.message}`
    );

  } finally {

    setLoading(false);
  }
}

// ======================================
// RENDER RESULTS
// ======================================

function renderResults(data) {

  document
    .getElementById("results")
    .classList.remove("hidden");

  // ====================================
  // RISK SCORE
  // ====================================

  const riskScore =
    data.risk_score || "N/A";

  const riskEl =
    document.getElementById(
      "riskScore"
    );

  riskEl.textContent =
    riskScore;

  riskEl.className =
    `stat-value ${getRiskClass(riskScore)}`;

  // ====================================
  // COUNTS
  // ====================================

  const threats =
    data.threats || [];

  const parsedLogs =
    data.parsed_logs || [];

  document
    .getElementById("threatCount")
    .textContent =
    threats.length;

  document
    .getElementById("logCount")
    .textContent =
    parsedLogs.length;

  // ====================================
  // THREATS
  // ====================================

  const threatsEl =
    document.getElementById(
      "threats"
    );

  if (threats.length) {

    threatsEl.innerHTML =

      threats.map((threat) => `

        <span class="tag tag-threat">
          ${escapeHtml(threat)}
        </span>

      `).join("");

  } else {

    threatsEl.innerHTML = `
      <p style="color:#94a3b8;">
        No threats detected
      </p>
    `;
  }

  // ====================================
  // MITRE DATA
  // ====================================

  const mitre =
    data.mitre_data || [];

  const mitreEl =
    document.getElementById(
      "mitre"
    );

  if (mitre.length) {

    mitreEl.innerHTML = `

      <table>

        <thead>

          <tr>
            <th>Threat</th>
            <th>MITRE ID</th>
            <th>Technique</th>
          </tr>

        </thead>

        <tbody>

          ${mitre.map((item) => `

            <tr>

              <td>
                ${escapeHtml(item.threat)}
              </td>

              <td>
                ${escapeHtml(item.mitre_id)}
              </td>

              <td>
                ${escapeHtml(item.technique)}
              </td>

            </tr>

          `).join("")}

        </tbody>

      </table>
    `;

  } else {

    mitreEl.innerHTML = `
      <p style="color:#94a3b8;">
        No MITRE Mapping Found
      </p>
    `;
  }

  // ====================================
  // THREAT INTELLIGENCE
  // ====================================

  const intel =
    data.threat_intel || [];

  const intelEl =
    document.getElementById(
      "intel"
    );

  if (intel.length) {

    intelEl.innerHTML = `

      <table>

        <thead>

          <tr>
            <th>IP Address</th>
            <th>Country</th>
            <th>Abuse Score</th>
          </tr>

        </thead>

        <tbody>

          ${intel.map((item) => `

            <tr>

              <td>
                ${escapeHtml(item.ip)}
              </td>

              <td>
                ${escapeHtml(item.country)}
              </td>

              <td>
                ${escapeHtml(
                  item.abuse_score
                )}
              </td>

            </tr>

          `).join("")}

        </tbody>

      </table>
    `;

  } else {

    intelEl.innerHTML = `
      <p style="color:#94a3b8;">
        No Threat Intelligence Found
      </p>
    `;
  }

  // ====================================
  // CVE DATA
  // ====================================

  const cves =
    data.cve_data || [];

  const cveEl =
    document.getElementById(
      "cves"
    );

  if (cves.length) {

    cveEl.innerHTML =

      cves.map((cve) => `

        <div class="cve-card">

          <h4>
            ${escapeHtml(cve.id)}
          </h4>

          <p>
            ${escapeHtml(
              cve.description ||
              "No description available"
            )}
          </p>

        </div>

      `).join("");

  } else {

    cveEl.innerHTML = `
      <p style="color:#94a3b8;">
        No CVEs Found
      </p>
    `;
  }

  // ====================================
  // REPORT
  // ====================================

  document
    .getElementById("report")
    .innerHTML =

    formatReport(data.report);

  // ====================================
  // RECOMMENDATIONS
  // ====================================

  document
    .getElementById("recommendations")
    .innerHTML =
    formatRecommendations(data.recommendations);
}

// ======================================
// AUTO LOAD SAMPLE
// ======================================

window.onload = () => {

  loadSample();
};

// ENTER KEY SUPPORT
document.getElementById("logs").addEventListener("keydown",
    function (event) {
      // Ctrl + Enter
      if (
        event.key === "Enter"
      ) {

        event.preventDefault();
        analyzeThreats();
      }
    }
  );