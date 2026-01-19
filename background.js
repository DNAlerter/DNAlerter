const BLOCKED_KEY = "blocked_domains";


async function isPublicNetwork() {
  try {
    const response = await fetch(chrome.runtime.getURL('is_threat'));
    if (!response.ok) return false;
    const text = await response.text();
    return text.trim() === '0';
  } catch (e) {
    console.error("DNAlerter: не удалось прочитать is_threat", e);
    return false;
  }
}

chrome.runtime.onStartup.addListener(updateBlocking);
chrome.runtime.onInstalled.addListener(updateBlocking);
chrome.action.onClicked.addListener(updateBlocking);

async function updateBlocking() {
  const publicNet = await isPublicNetwork();

  if (!publicNet) {
    await clearAllRules();
    await chrome.storage.local.set({ [BLOCKED_KEY]: [] });
    notifyPopup(0);
    return;
  }


  const cookies = await chrome.cookies.getAll({});
  const blocked = new Set();
  const SENSITIVE_NAMES = new Set("session,sessionid,sid,s,connect.sid,jsessionid,phpsessid,laravel_session,ci_session,next-auth.session-token,__secure-next-auth.session-token,__host-next-auth.session-token,authjs.session-token,__session,sb-access-token,sb-refresh-token,mspauth,mspauth1,mscc,wlid,wlidperf,nap,anon,asp.net_sessionid,.aspxauth,wordpress_logged_in_,token,access_token,refresh_token,id_token,jwt,bearer,auth_token,authtoken,user_session,auth_session,login_token,session_token,authorization,remember_token,vercel_jwt,__host-session,__secure-session,xsrf-token,csrftoken,_rails_session,_gitlab_session,gitlab_user,sp_dc,sp_key,token_v2,nf_jwt,nf_session,adobeid,cake,canva_session,trello_session,asana_session,zm_chtaid,cred,d,slack_session,customer_session,xman_us_f,ka_session,jwt_token,proton_session,auth_session_id,_shopify_s,_shopify_y,airtable_session,__host-figma_session".split(","));
  for (const c of cookies) {
    const nameLower = c.name.toLowerCase();
    
    if (
      SENSITIVE_NAMES.has(nameLower) ||                    
      nameLower.startsWith("_gitlab") ||
      nameLower.startsWith("sp_") ||                      
      nameLower.startsWith("nf_") ||                        
      nameLower.startsWith("zm_") ||                          
      nameLower.startsWith("token_v") ||                         
      nameLower.startsWith("ka_") ||                            
      nameLower.startsWith("duo") ||
      nameLower.startsWith("_shopify") ||
      nameLower.includes("session") || nameLower.includes("auth")
    ) {
      if (c.expirationDate) {
        let domain = c.domain;
        if (domain.startsWith(".")) domain = domain.slice(1);
        blocked.add(domain);
        if (!domain.startsWith("www.")) blocked.add("www." + domain);
      }
    }
  }

  await chrome.storage.local.set({ [BLOCKED_KEY]: [...blocked] });
  await applyRules([...blocked]);
  notifyPopup(blocked.size);
}

async function applyRules(domains) {
  const current = await chrome.declarativeNetRequest.getDynamicRules();
  const oldIds = current.map(r => r.id);

  const rules = domains.map((d, i) => ({
    id: i + 1,
    priority: 1,
    action: {
      type: "redirect",
      redirect: { url: chrome.runtime.getURL("blockpage.html") + "?url=" + encodeURIComponent("https://" + d) }
    },
    condition: {
      urlFilter: "||" + d + "^",
      resourceTypes: ["main_frame"]
    }
  }));

  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: oldIds,
    addRules: rules
  });
}

async function clearAllRules() {
  const current = await chrome.declarativeNetRequest.getDynamicRules();
  const oldIds = current.map(r => r.id);
  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: oldIds,
    addRules: []
  });
}

function notifyPopup(count) {
  chrome.runtime.sendMessage({
    action: "scanCompleted",
    count: count
  }).catch(() => {});
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg === "scan" || (msg.action && msg.action === "scanNow")) {
    updateBlocking();
    sendResponse({ ok: true });
    return true;
  }

  if (msg.action === "openWithoutCookies" && msg.domain) {
    (async () => {
      const clean = msg.domain.replace(/^www\./i, "");
      const cookies = await chrome.cookies.getAll({});

      for (const c of cookies) {
        const cd = c.domain.startsWith(".") ? c.domain.slice(1) : c.domain;
        if (cd === clean || cd.endsWith("." + clean)) {
          const url = (c.secure ? "https://" : "http://") + cd;
          await chrome.cookies.remove({ url, name: c.name, storeId: c.storeId });
        }
      }

      await updateBlocking();
      sendResponse({ ok: true });
    })();
    return true;
  }
});