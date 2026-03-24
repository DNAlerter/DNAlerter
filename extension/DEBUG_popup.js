const list = document.getElementById("list");
const status = document.getElementById("status");
const scanButton = document.getElementById("scanNow");

function updateList() {
  chrome.storage.local.get("blocked_domains", (data) => {
    const domains = data.blocked_domains || [];
    list.innerHTML = "";

    if (domains.length === 0) {
      list.innerHTML = "<li style='color:#666'>Нет заблокированных сайтов</li>";
      return;
    }

    domains.sort().forEach(domain => {
      const li = document.createElement("li");
      li.textContent = domain;
      list.appendChild(li);
    });
  });
}

scanButton.onclick = () => {
  scanButton.disabled = true;
  scanButton.textContent = "Сканирую...";
  status.textContent = "Поиск опасных кук...";

  chrome.runtime.sendMessage({ action: "scanNow" });
};

chrome.runtime.onMessage.addListener((msg) => {
  if (msg.action === "scanCompleted") {
    updateList();
    scanButton.disabled = false;
    scanButton.textContent = "Проверить куки";

    status.textContent = msg.count > 0
      ? `Найдено и заблокировано: ${msg.count} сайт(ов)`
      : "Опасных кук не найдено";

    setTimeout(() => status.textContent = "", 3000);
  }
});

updateList();


chrome.storage.onChanged.addListener((changes) => {
  if (changes.blocked_domains) updateList();
});