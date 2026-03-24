const params = new URLSearchParams(location.search);
const url = params.get("url") || "https://example.com";
document.getElementById("u").textContent = url;
document.getElementById("siteBlocked").textContent = new URL(url).hostname + " blocked";

const domain = new URL(url).hostname.replace(/^www\./i, "");

document.getElementById("nocookies").onclick = async () => {
  await chrome.runtime.sendMessage({ action: "openWithoutCookies", domain });
  location.href = url;
};