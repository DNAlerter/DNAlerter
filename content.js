const wordsToCheck = ['пароль', 'password'];
const pageContent = document.documentElement.innerHTML.toLowerCase();
let anythingFound = false;

async function readExtensionFile(filePath) {
    try {
        const response = await fetch(chrome.runtime.getURL(filePath));
        const contents = await response.text();
        console.log('File contents:', contents);
        return contents;
    } catch (error) {
        console.error('Error reading file:', error);
    }
}

wordsToCheck.forEach(word => {
  let isFound = false;

  const wordBoundaryRegex = new RegExp(`\\b${word}\\b`, 'g');
  const attributeRegex = new RegExp(`${word}\\s*=`, 'g');
  isFound = wordBoundaryRegex.test(pageContent) || attributeRegex.test(pageContent);
  if (isFound) {
    anythingFound = true;
	//alert("FOUND: "+word);
  }
});

async function AlertIfFound(isFound) {
    if (isFound){
		const content = await readExtensionFile('is_threat');
		if (content=='0'){
			alert('ВЫ ПОДКЛЮЧЕНЫ К НЕБЕЗОПАСНОЙ СЕТИ, ЕСТЬ РИСК ПОТЕРИ ПЕРСОНАЛЬНЫХ ДАННЫХ');
		}
	}
}

AlertIfFound(anythingFound)