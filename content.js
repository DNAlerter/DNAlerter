let isPublicNetwork = false;
let networkChecked = false;
let alertShown = false;

async function getNetworkStatus() {
    if (networkChecked) return;
    try {
        const resp = await fetch(chrome.runtime.getURL('is_threat'));
        console.log(chrome.runtime.getURL('is_threat'));
        console.log(resp);
        const text = await resp.text();
        isPublicNetwork = (text.trim() === '0');
        networkChecked = true;
    } catch (e) {
        isPublicNetwork = false;
    }
}

function hasSensitiveInput() {
    const inputs = document.querySelectorAll('input');
    const keywords = ['login', 'email', 'phone', 'tel', 'pass', 'password', 'телефон', 'логин', 'почта'];

    for (const input of inputs) {
        const attrs = [
            input.name || '',
            input.id || '',
            input.placeholder || '',
            input.getAttribute('aria-label') || '',
            input.getAttribute('data-testid') || ''
        ].join(' ').toLowerCase();

        if (keywords.some(word => attrs.includes(word))) {
            return true;
        }
    }
    return false;
}

async function protectPage() {
    await getNetworkStatus();

    if (!isPublicNetwork) return;

    let sensitive = hasSensitiveInput();

    if (sensitive && !alertShown) {
        alert('⚠️ Внимание!\nВы в общедоступной Wi-Fi сети.\nНе вводите личные данные!');
        alertShown = true;
    }

    if (sensitive) {
        const inputs = document.querySelectorAll('input, textarea');

        inputs.forEach(field => {
            if (field.type === 'hidden' || field.type === 'submit' || field.type === 'button' || 
                field.type === 'checkbox' || field.type === 'radio') {
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
            field.style.fontSize = '16px';
        });
    }
}

const observer = new MutationObserver(protectPage);

protectPage();
observer.observe(document.body, { childList: true, subtree: true });