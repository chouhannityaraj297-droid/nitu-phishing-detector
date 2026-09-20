/**
 * Content script that runs inside Gmail's page.
 * Finds open emails, extracts sender/subject/body/links, sends them to the
 * local backend API, and injects a colored risk badge next to the subject line.
 *
 * NOTE: Gmail's HTML structure changes over time and varies by view. The
 * selectors below target the "open email" view as of writing. If badges stop
 * appearing after a Gmail update, the selectors will need adjusting.
 */

const API_URL = "https://nitu-phishing-detector.onrender.com/analyze";
const processedEmails = new Set();

function extractEmailData(emailContainer) {
  try {
    const subjectEl = emailContainer.querySelector("h2");
    const subject = subjectEl ? subjectEl.innerText.trim() : "";

    const senderEl = emailContainer.querySelector("span[email]");
    const senderAddress = senderEl ? senderEl.getAttribute("email") : "";
    const senderName = senderEl ? senderEl.getAttribute("name") || senderEl.innerText : "";
    const rawSender = senderName ? `"${senderName}" <${senderAddress}>` : senderAddress;

    const bodyEl = emailContainer.querySelector("div[data-message-id] div.a3s");
    const bodyText = bodyEl ? bodyEl.innerText.trim() : "";

    const linkEls = bodyEl ? bodyEl.querySelectorAll("a[href]") : [];
    const urls = Array.from(linkEls)
      .map((a) => a.href)
      .filter((href) => href.startsWith("http"));

    if (!subject || !rawSender || !bodyText) return null;

    return { subject, body_text: bodyText, raw_sender: rawSender, urls, headers: {} };
  } catch (e) {
    console.warn("Phishing Detector: failed to extract email data", e);
    return null;
  }
}

function injectBadge(subjectEl, result) {
  if (subjectEl.parentElement.querySelector(".phish-badge")) return;

  const badge = document.createElement("span");
  badge.className = `phish-badge phish-badge-${result.verdict.toLowerCase()}`;
  badge.innerText = `${result.verdict} (${result.final_score}/100)`;

  const tooltip = document.createElement("div");
  tooltip.className = "phish-tooltip";
  tooltip.innerHTML = `<strong>Why flagged:</strong><ul>${result.reasons
    .map((r) => `<li>${r}</li>`)
    .join("")}</ul>`;

  subjectEl.parentElement.appendChild(badge);
  subjectEl.parentElement.appendChild(tooltip);
}

async function analyzeEmail(emailContainer) {
  const data = extractEmailData(emailContainer);
  if (!data) return;

  const emailKey = data.subject + data.raw_sender;
  if (processedEmails.has(emailKey)) return;
  processedEmails.add(emailKey);

  try {
    const response = await fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
    });
    if (!response.ok) throw new Error(`API returned ${response.status}`);
    const result = await response.json();

    const subjectEl = emailContainer.querySelector("h2");
    if (subjectEl) injectBadge(subjectEl, result);
  } catch (e) {
    console.warn("Phishing Detector: could not reach local API. Is it running?", e);
  }
}

function scanForOpenEmails() {
  const emailContainers = document.querySelectorAll("div[role='main']");
  emailContainers.forEach((container) => analyzeEmail(container));
}

// Gmail is a single-page app — content loads dynamically, so watch for changes
const observer = new MutationObserver(() => scanForOpenEmails());
observer.observe(document.body, { childList: true, subtree: true });

// Also run once on initial load
scanForOpenEmails();
