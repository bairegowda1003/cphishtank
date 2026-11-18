const BASE = import.meta.env.VITE_API_URL || "";

export const getToken = () => localStorage.getItem("cpt_token") || sessionStorage.getItem("cpt_token");
export const clearToken = () => {
  localStorage.removeItem("cpt_token");
  sessionStorage.removeItem("cpt_token");
};
export const storeToken = (token, remember = false) => {
  clearToken();
  (remember ? localStorage : sessionStorage).setItem("cpt_token", token);
};

async function request(path, { method = "GET", body, form } = {}) {
  const headers = {};
  const t = getToken();
  if (t) headers.Authorization = `Bearer ${t}`;
  if (body) headers["Content-Type"] = "application/json";
  let res;
  try {
    res = await fetch(`${BASE}${path}`, { method, headers, body: form || (body ? JSON.stringify(body) : undefined) });
  } catch {
    throw new Error("Can't reach the server. Check that the backend is running on port 8000.");
  }
  if (res.status === 204) return null;
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    if (res.status === 401) {
      clearToken();
      window.dispatchEvent(new Event("cpt:unauthorized"));
    }
    const d = data.detail;
    const error = new Error(typeof d === "string" ? d : Array.isArray(d) ? d.map((x) => x.msg).join(", ") : "Something went wrong.");
    error.status = res.status;
    throw error;
  }
  return data;
}

export const api = {
  login: (b) => request("/api/auth/login", { method: "POST", body: b }),
  register: (b) => request("/api/auth/register", { method: "POST", body: b }),
  verifyEmail: (b) => request("/api/auth/verify-email", { method: "POST", body: b }),
  resendOtp: (b) => request("/api/auth/resend-otp", { method: "POST", body: b }),
  forgotPassword: (b) => request("/api/auth/forgot-password", { method: "POST", body: b }),
  resetPassword: (b) => request("/api/auth/reset-password", { method: "POST", body: b }),
  changePassword: (b) => request("/api/auth/change-password", { method: "POST", body: b }),
  me: () => request("/api/auth/me"),
  scan: (b) => request("/api/scan", { method: "POST", body: b }),
  upload: (file, channel, save) => {
    const f = new FormData();
    f.append("file", file); f.append("channel", channel); f.append("save", save);
    return request("/api/scan/upload", { method: "POST", form: f });
  },
  scans: (q = "") => request(`/api/scans${q}`),
  scan_get: (id) => request(`/api/scans/${id}`),
  scan_delete: (id) => request(`/api/scans/${id}`, { method: "DELETE" }),
  feedback: (id, feedback) => request(`/api/scans/${id}/feedback`, { method: "PATCH", body: { feedback } }),
  myStats: () => request("/api/scans/stats/me"),
  surveyQuestions: () => request("/api/survey/questions"),
  surveySubmit: (b) => request("/api/survey", { method: "POST", body: b }),
  surveyStats: () => request("/api/survey/stats"),
  adminOverview: () => request("/api/admin/overview"),
  addLabeledMessage: (body) => request("/api/admin/labeled-message", { method: "POST", body }),
};
