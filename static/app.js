const form = document.getElementById("generator-form");
const lengthRange = document.getElementById("length-range");
const lengthNumber = document.getElementById("length-number");
const countInput = document.getElementById("count-input");
const useUpper = document.getElementById("use-upper");
const useLower = document.getElementById("use-lower");
const useDigits = document.getElementById("use-digits");
const useSymbols = document.getElementById("use-symbols");
const excludeAmbiguous = document.getElementById("exclude-ambiguous");
const excludeChars = document.getElementById("exclude-chars");
const passwordList = document.getElementById("password-list");
const resultsMeta = document.getElementById("results-meta");
const errorBanner = document.getElementById("error-banner");
const copyAllBtn = document.getElementById("copy-all-btn");

let latestPasswords = [];

lengthRange.addEventListener("input", () => {
  lengthNumber.value = lengthRange.value;
});

lengthNumber.addEventListener("input", () => {
  const val = Number(lengthNumber.value);
  if (!Number.isNaN(val)) {
    lengthRange.value = String(Math.min(64, Math.max(4, val)));
  }
});

function strengthSlug(label) {
  return label.toLowerCase().replace(/\s+/g, "-");
}

function showError(message) {
  errorBanner.textContent = message;
  errorBanner.hidden = false;
}

function clearError() {
  errorBanner.textContent = "";
  errorBanner.hidden = true;
}

async function copyText(text, buttonEl, defaultText) {
  try {
    await navigator.clipboard.writeText(text);
    buttonEl.textContent = "Copied!";
    setTimeout(() => {
      buttonEl.textContent = defaultText;
    }, 1400);
  } catch {
    buttonEl.textContent = "Copy failed";
    setTimeout(() => {
      buttonEl.textContent = defaultText;
    }, 1400);
  }
}

function renderPasswords(items) {
  passwordList.innerHTML = "";
  latestPasswords = items.map((item) => item.password);
  resultsMeta.textContent = `${items.length} password${items.length === 1 ? "" : "s"}`;

  for (const item of items) {
    const li = document.createElement("li");
    li.className = "password-item";

    const top = document.createElement("div");
    top.className = "password-top";

    const code = document.createElement("code");
    code.className = "password-value";
    code.textContent = item.password;

    const copyBtn = document.createElement("button");
    copyBtn.type = "button";
    copyBtn.className = "copy-btn";
    copyBtn.textContent = "Copy";
    copyBtn.addEventListener("click", () => copyText(item.password, copyBtn, "Copy"));

    top.append(code, copyBtn);

    const strengthRow = document.createElement("div");
    strengthRow.className = "strength-row";

    const slug = strengthSlug(item.strength);
    const track = document.createElement("div");
    track.className = "strength-track";

    const fill = document.createElement("div");
    fill.className = `strength-fill fill-${slug}`;
    track.appendChild(fill);

    const label = document.createElement("span");
    label.className = `strength-label strength-${slug}`;
    label.textContent = `${item.entropy} bits · ${item.strength}`;

    strengthRow.append(track, label);
    li.append(top, strengthRow);
    passwordList.appendChild(li);
  }
}

async function generate() {
  clearError();
  const payload = {
    length: Number(lengthNumber.value || 16),
    count: Number(countInput.value || 1),
    use_uppercase: useUpper.checked,
    use_lowercase: useLower.checked,
    use_digits: useDigits.checked,
    use_symbols: useSymbols.checked,
    exclude_ambiguous: excludeAmbiguous.checked,
    exclude_chars: excludeChars.value,
  };

  try {
    const response = await fetch("/api/generate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await response.json();
    if (!response.ok) {
      showError(data.error || "Failed to generate passwords.");
      return;
    }
    renderPasswords(data.passwords);
  } catch {
    showError("Unable to reach the local password generator server.");
  }
}

form.addEventListener("submit", (event) => {
  event.preventDefault();
  generate();
});

copyAllBtn.addEventListener("click", () => {
  if (latestPasswords.length === 0) return;
  copyText(latestPasswords.join("\n"), copyAllBtn, "Copy All");
});

generate();
