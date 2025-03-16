// popup.js (обновлённый, для отображения результатов по клику, если нужно)
document.addEventListener('DOMContentLoaded', function() {
  const wordsToCheck = ['пароль', 'логин', 'login', 'password','email','почта'];
  const resultsList = document.getElementById('results');
  chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
	localStorage["foundany"] = false;
    chrome.scripting.executeScript({
      target: { tabId: tabs[0].id },
      function: checkPageContent,
    }, (results) => {
      const pageContent = results[0].result.toLowerCase();

      wordsToCheck.forEach(word => {
        const li = document.createElement('li');
        let isFound = false;

        const wordBoundaryRegex = new RegExp(`\\b${word}\\b`, 'g');
        const attributeRegex = new RegExp(`${word}\\s*=`, 'g');
        isFound = wordBoundaryRegex.test(pageContent) || attributeRegex.test(pageContent);

        if (isFound) {
          li.textContent = `${word}: найдено`;
          li.className = 'found';
		  localStorage["foundany"] = true;
        } else {
          li.textContent = `${word}: не найдено`;
          li.className = 'not-found';
        }
        resultsList.appendChild(li);
      });
	  const x = document.getElementById('threat');
	  if (localStorage["foundany"]){
		x.append("THREAT");
		x.append(localStorage["is_threat"])
	  }
	  else{
		x.append("SAFE")
		x.append(localStorage["is_threat"])
	  }
	  });
    });
});

function checkPageContent() {
  return document.documentElement.innerHTML;
}