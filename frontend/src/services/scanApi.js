
const API_URL = import.meta.env.VITE_API_URL;

export async function scanWebsite(url) {
  const response = await fetch(`${API_URL}/scan`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ url }),
  });

  const data = await response.json();

  if (!response.ok) {
    throw new Error(
      data.detail || "Website scanning failed."
    );
  }

  return data;
}
