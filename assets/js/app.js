/**
 * Smart Password Security Lab - UI Application Controller.
 *
 * Manages live debounced analysis, custom dictionary File API,
 * JSON export, Learning Mode, Show/Hide, and accessible announcements.
 * Guarantees zero local persistence, zero network requests, and DOM safety.
 */

"use strict";

(function () {
  const analyzer = window.PasswordAnalyzer;
  if (!analyzer) {
    console.error("PasswordAnalyzer core engine not loaded.");
    return;
  }

  // State
  let inMemoryCustomDict = null;
  let currentAnalysisResult = null;
  let debounceTimer = null;

  // DOM Elements
  const passwordInput = document.getElementById("passwordInput");
  const toggleVisibilityBtn = document.getElementById("toggleVisibilityBtn");
  const analyzeBtn = document.getElementById("analyzeBtn");
  const clearBtn = document.getElementById("clearBtn");
  const clearAllBtn = document.getElementById("clearAllBtn");
  const exportJsonBtn = document.getElementById("exportJsonBtn");
  const printPdfBtn = document.getElementById("printPdfBtn");
  const statusAnnouncer = document.getElementById("statusAnnouncer");

  // Custom Dictionary Elements
  const dictFileInput = document.getElementById("dictFileInput");
  const dictBadge = document.getElementById("dictBadge");
  const clearDictBtn = document.getElementById("clearDictBtn");

  // Result Elements
  const resultsCard = document.getElementById("resultsCard");
  const classificationTitle = document.getElementById("classificationTitle");
  const scoreValue = document.getElementById("scoreValue");
  const meterFill = document.getElementById("meterFill");
  const meterProgress = document.getElementById("meterProgress");
  const meterLabel = document.getElementById("meterLabel");
  const lengthPill = document.getElementById("lengthPill");
  const criteriaGrid = document.getElementById("criteriaGrid");
  const penaltiesSection = document.getElementById("penaltiesSection");
  const penaltiesList = document.getElementById("penaltiesList");
  const entropySummary = document.getElementById("entropySummary");
  const entropyDetails = document.getElementById("entropyDetails");
  const recommendationsList = document.getElementById("recommendationsList");

  // Learning Mode
  const learnBtns = document.querySelectorAll(".example-btn");
  const learnExplanation = document.getElementById("learnExplanation");

  const classificationPresentations = {
    "Very Weak": { color: "var(--accent-red)", fill: 18 },
    "Weak": { color: "var(--accent-orange)", fill: 35 },
    "Moderate": { color: "var(--accent-yellow)", fill: 55 },
    "Strong": { color: "var(--accent-cyan)", fill: 75 },
    "Very Strong": { color: "var(--accent-green)", fill: 95 }
  };

  const recommendationDescriptions = {
    "REC_INCREASE_LENGTH": "Increase password length to at least 12 characters (15+ for critical accounts).",
    "REC_CONSIDER_15_PLUS": "Consider reaching 15+ characters or adopting a multi-word passphrase.",
    "REC_CHOOSE_UNRELATED_PHRASE": "Avoid common dictionary words or predictable variants; use distinct words.",
    "REC_REMOVE_SEQUENCES": "Eliminate sequential characters (e.g. 1234, abcd) across keys.",
    "REC_REMOVE_REPEATS": "Avoid repeating identical characters consecutively.",
    "REC_REMOVE_KEYBOARD_WALK": "Avoid adjacent keyboard patterns (e.g. qwerty, asdf).",
    "REC_REMOVE_YEAR": "Avoid appending four-digit year numbers to base words.",
    "REC_DIVERSIFY_CASING": "Mix uppercase and lowercase characters where supported.",
    "REC_INCLUDE_DIGITS": "Include digits in unpredictable positions.",
    "REC_INCLUDE_SYMBOLS": "Include punctuation or symbols where supported.",
    "REC_USE_PASSWORD_MANAGER": "Store long, unique passwords in a reputable password manager."
  };

  function announce(message) {
    if (statusAnnouncer) {
      statusAnnouncer.textContent = message;
    }
  }

  function renderAnalysis(password, isExplicit = false) {
    if (!password || password.length === 0) {
      resultsCard.hidden = true;
      currentAnalysisResult = null;
      if (isExplicit) announce("Enter a password to analyze.");
      return;
    }

    const res = analyzer.analyzePassword(password, inMemoryCustomDict);
    currentAnalysisResult = res;

    resultsCard.hidden = false;

    // Score & Classification
    const classification = res.classification;
    const score = res.score;
    const pres = classificationPresentations[classification] || classificationPresentations["Very Weak"];

    classificationTitle.textContent = classification;
    classificationTitle.className = "classification-title " + classification.toLowerCase().replace(/\s+/g, "-");
    scoreValue.textContent = score;

    meterFill.style.width = pres.fill + "%";
    meterFill.style.backgroundColor = pres.color;
    meterProgress.setAttribute("aria-valuenow", String(score));
    meterLabel.textContent = `Score: ${score}/100 · ${classification}`;

    // Length Guidance
    lengthPill.textContent = `${res.length_guidance} (${res.length_code_points} Unicode code points)`;

    // Criteria Checklist
    criteriaGrid.replaceChildren();
    const criteriaItems = [
      { label: "12+ Characters", pass: res.criteria.length_target_met },
      { label: "Uppercase (A-Z)", pass: res.criteria.has_uppercase },
      { label: "Lowercase (a-z)", pass: res.criteria.has_lowercase },
      { label: "Digit (0-9)", pass: res.criteria.has_digits },
      { label: "Symbol / Punctuation", pass: res.criteria.has_symbols }
    ];

    for (const c of criteriaItems) {
      const el = document.createElement("div");
      el.className = "criterion-item " + (c.pass ? "pass" : "fail");
      const icon = document.createElement("span");
      icon.className = "criterion-icon";
      icon.setAttribute("aria-hidden", "true");
      icon.textContent = c.pass ? "✓" : "✗";
      const lbl = document.createElement("span");
      lbl.textContent = c.label;
      el.append(icon, lbl);
      criteriaGrid.appendChild(el);
    }

    // Penalties & Pattern Findings
    penaltiesList.replaceChildren();
    if (res.pattern_penalties.length > 0) {
      penaltiesSection.hidden = false;
      for (const p of res.pattern_penalties) {
        const item = document.createElement("li");
        item.className = "penalty-item";
        item.textContent = `-${p.penalty} pts [${p.rule_id}]: ${p.description}`;
        penaltiesList.appendChild(item);
      }
    } else {
      penaltiesSection.hidden = true;
    }

    // Entropy & Caveats
    const ent = res.entropy_estimate;
    if (ent.status === "CALCULATED") {
      entropySummary.textContent = `Theoretical Upper-Bound Entropy: ~${ent.bits} bits (Pool: ${ent.pool_size} chars)`;
      entropyDetails.textContent = `${ent.disclaimer} Note: Uniform Shannon entropy reflects an idealized attacker without dictionary heuristics; human passwords with patterns have significantly lower empirical entropy.`;
    } else {
      entropySummary.textContent = "Theoretical Entropy: Uncalibrated for non-ASCII Unicode";
      entropyDetails.textContent = "Contains characters beyond ASCII. Entropy estimation is omitted, and length and pattern weights have been automatically renormalized.";
    }

    // Practical Recommendations
    recommendationsList.replaceChildren();
    for (const rid of res.recommendation_ids) {
      const li = document.createElement("li");
      li.textContent = recommendationDescriptions[rid] || rid;
      recommendationsList.appendChild(li);
    }

    if (isExplicit) {
      announce(`Analysis complete. Assessment: ${classification}, Score: ${score}/100.`);
    }
  }

  // Live Debounced Input
  passwordInput.addEventListener("input", () => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
      renderAnalysis(passwordInput.value, false);
    }, 150);
  });

  // Explicit Analyze Button
  analyzeBtn.addEventListener("click", () => {
    renderAnalysis(passwordInput.value, true);
    passwordInput.focus();
  });

  // Show / Hide Password Toggle
  toggleVisibilityBtn.addEventListener("click", () => {
    const isPassword = passwordInput.type === "password";
    passwordInput.type = isPassword ? "text" : "password";
    toggleVisibilityBtn.textContent = isPassword ? "Hide" : "Show";
    toggleVisibilityBtn.setAttribute("aria-pressed", String(isPassword));
    toggleVisibilityBtn.setAttribute("aria-label", isPassword ? "Hide password characters" : "Show password characters");
    passwordInput.focus();
  });

  // Clear Action
  clearBtn.addEventListener("click", () => {
    passwordInput.value = "";
    passwordInput.type = "password";
    toggleVisibilityBtn.textContent = "Show";
    toggleVisibilityBtn.setAttribute("aria-pressed", "false");
    resultsCard.hidden = true;
    currentAnalysisResult = null;
    announce("Password input cleared.");
    passwordInput.focus();
  });

  // Clear All Action (Resets Input AND Custom Dictionary)
  clearAllBtn.addEventListener("click", () => {
    passwordInput.value = "";
    passwordInput.type = "password";
    toggleVisibilityBtn.textContent = "Show";
    toggleVisibilityBtn.setAttribute("aria-pressed", "false");
    resultsCard.hidden = true;
    currentAnalysisResult = null;

    inMemoryCustomDict = null;
    dictFileInput.value = "";
    dictBadge.hidden = true;
    clearDictBtn.hidden = true;

    announce("All password inputs and custom dictionary data have been cleared from memory.");
    passwordInput.focus();
  });

  // Custom Dictionary File Picker
  dictFileInput.addEventListener("change", (e) => {
    const file = e.target.files && e.target.files[0];
    if (!file) return;

    if (file.size > 1024 * 1024) {
      announce("Error: Custom dictionary file exceeds 1 MiB limit.");
      dictFileInput.value = "";
      return;
    }

    const reader = new FileReader();
    reader.onload = function (evt) {
      try {
        const text = evt.target.result;
        const lines = text.split(/\r?\n/);
        const entries = new Set();
        for (const line of lines) {
          const trimmed = line.trim().toLowerCase();
          if (trimmed && !trimmed.startsWith("#") && Array.from(trimmed).length <= 256) {
            entries.add(trimmed);
          }
          if (entries.size > 10000) {
            announce("Error: Custom dictionary exceeds maximum limit of 10,000 entries.");
            dictFileInput.value = "";
            return;
          }
        }
        inMemoryCustomDict = entries;
        dictBadge.textContent = `Custom dictionary: ${entries.size} entries loaded`;
        dictBadge.hidden = false;
        clearDictBtn.hidden = false;
        announce(`Custom dictionary loaded into memory (${entries.size} entries). Re-evaluating.`);
        renderAnalysis(passwordInput.value, true);
      } catch (err) {
        announce("Error reading custom dictionary file.");
      }
    };
    reader.onerror = function () {
      announce("Failed to read file.");
    };
    reader.readAsText(file, "UTF-8");
  });

  // Clear Custom Dictionary Only
  clearDictBtn.addEventListener("click", () => {
    inMemoryCustomDict = null;
    dictFileInput.value = "";
    dictBadge.hidden = true;
    clearDictBtn.hidden = true;
    announce("Custom dictionary cleared from memory.");
    renderAnalysis(passwordInput.value, true);
  });

  // JSON Export (Password-Free Allowlisted Data)
  exportJsonBtn.addEventListener("click", () => {
    if (!currentAnalysisResult) {
      announce("No active analysis result to export.");
      return;
    }
    const exportData = analyzer.generateAllowlistedExport(currentAnalysisResult, true);
    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "smart_password_security_report.json";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    announce("Sanitized JSON report exported.");
  });

  // Print to PDF
  printPdfBtn.addEventListener("click", () => {
    if (!currentAnalysisResult) {
      announce("Analyze a password before printing the report.");
      return;
    }
    window.print();
  });

  // Learning Mode Synthetic Examples
  const eduNotes = {
    "password123": "Notice how common-word matching caps the score at 29 (Weak) despite having 11 characters, lowercase, digits, and reaching basic criteria. Character complexity alone does not overcome predictable common words.",
    "Tiger!Qwerty2026": "A 16-character candidate that includes uppercase, lowercase, numbers, and symbols is penalized by the keyboard walk detector ('qwerty'), capping the classification at Weak. Predictable keyboard clusters are prioritized by dictionary tools.",
    "Abcd1234!!!!": "Shows multiple non-overlapping sequence penalties ('abcd', '1234') plus consecutive character repetition ('!!!!'). These compound to reduce the pattern score significantly.",
    "Correct-Horse-Battery-Staple-2026!": "A long, memorable multi-word passphrase (35 characters). It achieves a Very Strong rating (95/100). The engine does NOT penalize it for containing dictionary words as substrings because matching compares whole candidates."
  };

  learnBtns.forEach((btn) => {
    btn.addEventListener("click", () => {
      const sample = btn.getAttribute("data-sample");
      if (!sample) return;
      passwordInput.value = sample;
      renderAnalysis(sample, true);
      learnExplanation.textContent = eduNotes[sample] || "";
      learnExplanation.hidden = false;
      announce(`Loaded Learning Mode synthetic example.`);
    });
  });
})();
