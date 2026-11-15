const API_URL = (import.meta.env.VITE_API_URL || "http://127.0.0.1:8000").replace(/\/$/, "");

export async function scanWebsite(url, token) {
  const response = await fetch(`${API_URL}/scan`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ url }),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.detail || `Website scanning failed (HTTP ${response.status}).`);
  return data;
}

export async function fetchScanHistory(token) {
  const response = await fetch(`${API_URL}/scans`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.detail || `Could not load scan history (HTTP ${response.status}).`);
  if (!Array.isArray(data.history)) throw new Error("The server returned an invalid scan-history response.");
  return data.history;
}
