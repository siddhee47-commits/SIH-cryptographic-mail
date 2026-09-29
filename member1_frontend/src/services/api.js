const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

export async function analyzePcap(file) {
  const formData = new FormData();

  formData.append("file", file);

  const response = await fetch(
    `${API_BASE_URL}/analyze`,
    {
      method: "POST",
      body: formData
    }
  );

  if (!response.ok) {
    let message =
      `Backend returned HTTP ${response.status}.`;

    try {
      const body = await response.json();

      message =
        body.detail ||
        body.message ||
        message;
    } catch {
      // Keep default error message.
    }

    throw new Error(message);
  }

  return response.json();
}