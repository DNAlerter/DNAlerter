let isPublicNetwork = false;
let networkChecked = false;
let alertShown = false;

const SERVER_PORT = 4756;

async function getNetworkStatus() {
    if (networkChecked) return;

    try {
        const response = await chrome.runtime.sendMessage({ action: "getNetworkStatus" });
        isPublicNetwork = response.isPublic;
    } catch (e) {
        console.error("Не удалось получить статус сети из background", e);
        isPublicNetwork = false;
    }

    networkChecked = true;
}
function hasSensitiveInput() {
    const inputs = document.querySelectorAll('input');
    const keywords = ['login', 'email', 'phone', 'tel', 'pass', 'password', 'телефон', 'логин', 'почта'];
    
    for (const input of inputs) {
        const attrs = [
            (input.name || '').toLowerCase(),
            (input.id || '').toLowerCase(),
            (input.placeholder || '').toLowerCase(),
            (input.getAttribute('aria-label') || '').toLowerCase(),
            (input.getAttribute('data-testid') || '').toLowerCase()
        ].join(' ');

        if (keywords.some(word => attrs.includes(word))) {
            return true;
        }
    }
    return false;
}

async function protectPage() {
    await getNetworkStatus();

    if (!isPublicNetwork) return;

    const hasSensitive = hasSensitiveInput();

    if (hasSensitive && !alertShown) {
        alert('⚠️ Внимание!\nВы в общедоступной Wi-Fi сети.\nНе вводите личные данные!');
        alertShown = true;
    }

    if (hasSensitive) {
        const fields = document.querySelectorAll('input, textarea');
        fields.forEach(field => {
            if (
                field.type === 'hidden' ||
                field.type === 'submit' ||
                field.type === 'button' ||
                field.type === 'checkbox' ||
                field.type === 'radio' ||
                field.type === 'image' ||
                field.type === 'file'
            ) {
                return;
            }

            field.disabled = true;
            field.readOnly = true;

            if (field.type === 'password') {
                field.type = 'text';
            }

            field.value = 'Сеть небезопасна! Не вводите данные';
            field.style.color = '#d32f2f';
            field.style.fontWeight = 'bold';
            field.style.backgroundColor = '#ffebee';
            field.style.fontSize = '15px';
            field.style.border = '2px solid #d32f2f';
        });
    }
}

protectPage();

const observer = new MutationObserver(() => {
    protectPage();
});

observer.observe(document.body, {
    childList: true,
    subtree: true,
    attributes: true,
    attributeFilter: ['type', 'name', 'id', 'placeholder']
});