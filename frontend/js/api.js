// Point d'accès à l'API backend. En dev via docker-compose, le backend
// écoute sur localhost:8000 (port mappé) même si le frontend tourne aussi
// dans un conteneur — le navigateur, lui, sort toujours par localhost.
const API_BASE = "http://localhost:8000";

const api = {
  token() {
    return localStorage.getItem("token");
  },

  async request(path, options = {}) {
    const headers = options.headers || {};
    const token = this.token();
    if (token) headers["Authorization"] = `Bearer ${token}`;
    if (options.body && !(options.body instanceof URLSearchParams)) {
      headers["Content-Type"] = "application/json";
    }

    const res = await fetch(`${API_BASE}${path}`, { ...options, headers });

    if (res.status === 401) {
      localStorage.removeItem("token");
      window.location.href = "index.html";
      return;
    }
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      const detail = data.detail;
      const message = Array.isArray(detail)
        ? detail.map((d) => d.msg).join(" ")
        : detail || `Erreur ${res.status}`;
      throw new Error(message);
    }
    if (res.status === 204) return null;
    return res.json();
  },

  async login(username, password) {
    const body = new URLSearchParams({ username, password });
    const data = await this.request("/auth/login", { method: "POST", body });
    localStorage.setItem("token", data.access_token);
    return data;
  },

  async register(username, email, password, organization) {
    return this.request("/auth/register", {
      method: "POST",
      body: JSON.stringify({ username, email, password, organization: organization || null }),
    });
  },

  logout() {
    localStorage.removeItem("token");
    window.location.href = "index.html";
  },

  getMe() { return this.request("/auth/me"); },

  getScans() { return this.request("/scans"); },
  async downloadReport(scanId, target) {
    const res = await fetch(`${API_BASE}/scans/${scanId}/report`, {
      headers: { Authorization: `Bearer ${this.token()}` },
    });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data.detail || "Impossible de générer le rapport.");
    }
    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `rapport_${(target || "scan").replace(/[^a-z0-9]/gi, "_")}_${scanId}.pdf`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(url);
  },
  getAllVulnerabilities() { return this.request("/scans/vulnerabilities"); },
  updateVulnerabilityStatus(vulnId, status) {
    return this.request(`/scans/vulnerabilities/${vulnId}/status`, {
      method: "PATCH", body: JSON.stringify({ status }),
    });
  },
  pollScan(id) { return this.request(`/scans/${id}`); },
  compareScan(id) { return this.request(`/scans/${id}/compare`); },
  getScan(id) { return this.request(`/scans/${id}`); },
  createScan(url, scanner) {
    return this.request("/scans", { method: "POST", body: JSON.stringify({ url, scanner }) });
  },
  deleteScan(id) { return this.request(`/scans/${id}`, { method: "DELETE" }); },

  getSchedules() { return this.request("/schedule"); },
  createSchedule(target, frequency, scanner, scheduledAt) {
    return this.request("/schedule", { method: "POST", body: JSON.stringify({ target, frequency, scanner, scheduled_at: scheduledAt || null }) });
  },
  cancelSchedule(id) { return this.request(`/schedule/${id}`, { method: "DELETE" }); },

  getAuditLogs() { return this.request("/audit"); },
  getDashboardStats() { return this.request("/stats/dashboard"); },
};
