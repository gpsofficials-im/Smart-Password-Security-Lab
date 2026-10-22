/**
 * Smart Password Security Lab - Pure JavaScript Analysis Engine.
 *
 * Provides 100% parity with password_analyzer.py.
 * Pure analysis: no network requests, no DOM access, no local storage.
 * Works both as an ES module and in standard browser script environments.
 */

"use strict";

const ANALYSIS_VERSION = "2.0.0";

const DEFAULT_BUNDLED_PASSWORDS = new Set([
  "123456", "password", "12345678", "qwerty", "123456789", "12345",
  "1234", "111111", "1234567", "dragon", "123123", "baseball",
  "iloveyou", "trustno1", "sunshine", "master", "welcome", "shadow",
  "ashley", "football", "jesus", "michael", "ninja", "mustang",
  "password1", "password123", "admin", "letmein", "monkey", "access",
  "hello", "charlie", "donald", "princess", "qwerty123", "admin123",
  "root", "toor", "pass", "test", "guest", "master123", "changeme",
  "orange", "secret", "123qwe", "zxcvbn", "1234567890", "password12",
  "login", "welcome1", "qwertyuiop", "testing123", "superman", "batman",
  "administrator", "passcode", "default", "operator", "service"
]);

const COMMON_BASES = [
  "password", "admin", "qwerty", "welcome", "letmein", "iloveyou",
  "monkey", "dragon", "login", "changeme", "master", "guest",
  "football", "baseball", "superman", "batman", "shadow", "sunshine",
  "access", "testing", "default", "orange", "secret", "charlie"
];

const KEYBOARD_WALK_PATTERNS = [
  // Horizontal forward/reverse
  "qwertyuiop", "poiuytrewq",
  "asdfghjkl", "lkjhgfdsa",
  "zxcvbnm", "mnbvcxz",
  "1234567890", "0987654321",
  // Vertical/diagonal column walks
  "1qaz", "zaq1",
  "2wsx", "xsw2",
  "3edc", "cde3",
  "4rfv", "vfr4",
  "5tgb", "bgt5",
  "6yhn", "nhy6",
  "7ujm", "mju7",
  "8ik,", ",ki8",
  "9ol.", ".lo9",
  // Gaming clusters
  "wasd", "dsaw",
  "qwer", "rewq"
];

const LEET_MAP = {
  "@": "a",
  "$": "s",
  "0": "o",
  "1": "i",
  "3": "e",
  "4": "a",
  "5": "s",
  "7": "t"
};

function countCodePoints(text) {
  return Array.from(text).length;
}

function detectSequences(password, minimumRun = 4) {
  const compact = password.replace(/[^a-zA-Z0-9]/g, "").toLowerCase();
  if (compact.length < minimumRun) return 0;

  let runsFound = 0;
  let i = 0;
  while (i < compact.length) {
    let runLen = 1;
    let delta = 0;
    let j = i + 1;
    while (j < compact.length) {
      const prev = compact[j - 1];
      const curr = compact[j];
      const sameType = (/[a-z]/.test(prev) && /[a-z]/.test(curr)) || (/[0-9]/.test(prev) && /[0-9]/.test(curr));
      if (!sameType) break;
      const d = curr.charCodeAt(0) - prev.charCodeAt(0);
      if (d === 1 || d === -1) {
        if (runLen === 1) {
          delta = d;
          runLen += 1;
        } else if (d === delta) {
          runLen += 1;
        } else {
          break;
        }
      } else {
        break;
      }
      j += 1;
    }
    if (runLen >= minimumRun) {
      runsFound += 1;
      i += runLen;
    } else {
      i += 1;
    }
  }
  return runsFound;
}

function detectRepeatedRuns(password, minimumRun = 4) {
  return new RegExp("(.)\\1{" + (minimumRun - 1) + ",}", "su").test(password);
}

function detectKeyboardWalks(password, minimumRun = 4) {
  const compact = password.replace(/[^a-zA-Z0-9]/g, "").toLowerCase();
  if (compact.length < minimumRun) return false;

  for (const walk of KEYBOARD_WALK_PATTERNS) {
    for (let k = 0; k <= walk.length - minimumRun; k += 1) {
      const sub = walk.substring(k, k + minimumRun);
      if (compact.includes(sub)) return true;
    }
  }
  return false;
}

function detectYearSuffix(password, bundledSet = DEFAULT_BUNDLED_PASSWORDS) {
  const lowered = password.toLowerCase();
  const match = lowered.match(/^([a-z]{3,})(19\d{2}|20\d{2})$/);
  if (match) {
    const base = match[1];
    if (COMMON_BASES.includes(base) || bundledSet.has(base)) {
      return true;
    }
  }
  return false;
}

function detectCommonVariant(password, bundledSet = DEFAULT_BUNDLED_PASSWORDS) {
  const lowered = password.toLowerCase();
  if (bundledSet.has(lowered)) return true;

  const compact = lowered.replace(/[^a-z0-9]/g, "");
  if (bundledSet.has(compact)) return true;

  const leetText = lowered.replace(/[@$013457]/g, (ch) => LEET_MAP[ch] || ch);
  const leetCompact = leetText.replace(/[^a-z0-9]/g, "");
  if (bundledSet.has(leetCompact)) return true;

  const candidates = [compact, leetCompact];
  for (const cand of candidates) {
    for (const root of COMMON_BASES) {
      const regex = new RegExp("^" + root + "[0-9]{1,4}$");
      if (regex.test(cand) || cand === root) return true;
    }
  }
  return false;
}

function calculateEntropy(password) {
  const length = countCodePoints(password);
  if (length === 0) {
    return {
      bits: 0.0,
      pool_size: 0,
      normalized_score: 0.0,
      status: "CALCULATED",
      warning: null,
      disclaimer: "Theoretical upper-bound based on uniform random selection."
    };
  }

  // Check ASCII
  const isAscii = /^[\x00-\x7F]*$/.test(password);
  if (!isAscii) {
    return {
      bits: null,
      pool_size: null,
      normalized_score: null,
      status: "UNAVAILABLE_NON_ASCII",
      warning: "ENTROPY_UNCALIBRATED_UNICODE",
      disclaimer: "Entropy calculation uncalibrated for non-ASCII Unicode code points."
    };
  }

  let poolSize = 0;
  if (/[a-z]/.test(password)) poolSize += 26;
  if (/[A-Z]/.test(password)) poolSize += 26;
  if (/[0-9]/.test(password)) poolSize += 10;
  if (/[!"#$%&'()*+,\-./:;<=>?@[\\\]^_`{|}~]/.test(password)) poolSize += 32;
  if (password.includes(" ")) poolSize += 1;

  let bits = 0.0;
  if (poolSize > 1) {
    bits = Math.round(length * Math.log2(poolSize) * 100) / 100;
  }

  const normalizedScore = Math.min(100.0, Math.round((bits / 80.0) * 100 * 100) / 100);

  return {
    bits,
    pool_size: poolSize,
    normalized_score: normalizedScore,
    status: "CALCULATED",
    warning: null,
    disclaimer: "Theoretical upper-bound assuming uniform random selection over character pool."
  };
}

function analyzePassword(password, customDictSet = null, bundledSet = DEFAULT_BUNDLED_PASSWORDS) {
  const length = countCodePoints(password);
  const lowered = password.toLowerCase();

  // Core character composition
  const hasLowercase = /[a-z]/.test(password);
  const hasUppercase = /[A-Z]/.test(password);
  const hasDigits = /[0-9]/.test(password);
  const hasSymbols = /[^A-Za-z0-9\s]/.test(password);
  const lengthTargetMet = length >= 12;

  // Length guidance
  let lengthGuidance = "";
  if (length === 0) {
    lengthGuidance = "Empty password";
  } else if (length < 8) {
    lengthGuidance = `Critically short (${length} code points; minimum 12 recommended)`;
  } else if (length < 12) {
    lengthGuidance = `Below minimum recommendation (${length}/12 code points)`;
  } else if (length < 15) {
    lengthGuidance = `Meets basic length target (${length}/12 code points); 15+ recommended for passphrases`;
  } else {
    lengthGuidance = `Meets robust length target (${length} code points)`;
  }

  // Dictionary checks (exact whole-word)
  const isBundledExact = length > 0 && bundledSet.has(lowered);
  const isCustomExact = length > 0 && customDictSet !== null && customDictSet.has(lowered);

  // Pattern detectors
  const sequenceCount = length >= 4 ? detectSequences(password) : 0;
  const repeatedRun = length >= 4 ? detectRepeatedRuns(password) : false;
  const keyboardWalk = length >= 4 ? detectKeyboardWalks(password) : false;
  const yearSuffix = length >= 5 ? detectYearSuffix(password, bundledSet) : false;
  const commonVariant = (length > 0 && !isBundledExact && !isCustomExact) ? detectCommonVariant(password, bundledSet) : false;

  // Penalties
  const patternPenalties = [];
  let totalPenalty = 0;

  if (sequenceCount > 0) {
    const penalty = Math.min(35, sequenceCount * 25);
    patternPenalties.push({
      rule_id: "PATTERN_ASCENDING_SEQUENCE",
      penalty,
      description: `Detected ${sequenceCount} sequential alphanumeric run(s) of 4+ characters.`
    });
    totalPenalty += penalty;
  }

  if (repeatedRun) {
    patternPenalties.push({
      rule_id: "PATTERN_REPEATED_RUN",
      penalty: 20,
      description: "Detected 4 or more identical consecutive characters."
    });
    totalPenalty += 20;
  }

  if (keyboardWalk) {
    patternPenalties.push({
      rule_id: "PATTERN_KEYBOARD_WALK",
      penalty: 25,
      description: "Detected 4 or more contiguous keys in a standard QWERTY keyboard walk."
    });
    totalPenalty += 25;
  }

  if (yearSuffix) {
    patternPenalties.push({
      rule_id: "PATTERN_YEAR_SUFFIX",
      penalty: 10,
      description: "Detected predictable four-digit year suffix (1900-2099) following a common base."
    });
    totalPenalty += 10;
  }

  if (commonVariant) {
    patternPenalties.push({
      rule_id: "PATTERN_COMMON_VARIANT",
      penalty: 25,
      description: "Resembles a common predictable password variant or substitution."
    });
    totalPenalty += 25;
  }

  if (isBundledExact) {
    patternPenalties.push({
      rule_id: "DICT_BUNDLED_EXACT",
      penalty: 90,
      description: "Exact match against offline bundled common passwords list."
    });
    totalPenalty += 90;
  }

  if (isCustomExact) {
    patternPenalties.push({
      rule_id: "DICT_CUSTOM_EXACT",
      penalty: 90,
      description: "Exact match against user-provided custom dictionary."
    });
    totalPenalty += 90;
  }

  // Scoring
  const lengthComponent = Math.min(100, 5 * length);
  const entropyInfo = calculateEntropy(password);
  const patternComponent = Math.max(0, 100 - totalPenalty);

  let baseScore = 0;
  if (length === 0) {
    baseScore = 0;
  } else if (entropyInfo.status === "CALCULATED" && entropyInfo.normalized_score !== null) {
    baseScore = Math.round(0.55 * lengthComponent + 0.15 * entropyInfo.normalized_score + 0.30 * patternComponent);
  } else {
    baseScore = Math.round((0.55 * lengthComponent + 0.30 * patternComponent) / 0.85);
  }
  baseScore = Math.max(0, Math.min(100, baseScore));

  // Severity caps
  let score = baseScore;
  let appliedCap = null;
  if (isBundledExact || isCustomExact) {
    appliedCap = 9;
  } else if (commonVariant) {
    appliedCap = 29;
  } else if (length < 8) {
    appliedCap = 19;
  } else if (length < 12) {
    appliedCap = 49;
  } else if (length < 15) {
    appliedCap = 69;
  }

  if (appliedCap !== null) {
    score = Math.min(score, appliedCap);
  }

  // Classification
  let classification = "Very Weak";
  if (score <= 19) classification = "Very Weak";
  else if (score <= 39) classification = "Weak";
  else if (score <= 59) classification = "Moderate";
  else if (score <= 79) classification = "Strong";
  else classification = "Very Strong";

  if (commonVariant && (classification === "Moderate" || classification === "Strong" || classification === "Very Strong")) {
    classification = "Weak";
  }

  // Warnings
  const warnings = [];
  if (isBundledExact) {
    warnings.push({
      id: "WARN_COMMON_PASSWORD",
      severity: "critical",
      message: "This password appears verbatim in standard lists of common credentials."
    });
  }
  if (isCustomExact) {
    warnings.push({
      id: "WARN_CUSTOM_DICTIONARY_MATCH",
      severity: "critical",
      message: "This password matches an entry in your specified custom dictionary."
    });
  }
  if (commonVariant) {
    warnings.push({
      id: "WARN_COMMON_VARIANT",
      severity: "high",
      message: "This password is an easily guessed variant of a common password."
    });
  }
  if (length > 0 && length < 8) {
    warnings.push({
      id: "WARN_CRITICALLY_SHORT",
      severity: "high",
      message: "Password is critically short and can be cracked rapidly via brute-force."
    });
  } else if (length > 0 && length < 12) {
    warnings.push({
      id: "WARN_SUB_RECOMMENDED_LENGTH",
      severity: "medium",
      message: "Password length is below the 12-character baseline target."
    });
  }
  if (sequenceCount > 0 || repeatedRun || keyboardWalk) {
    warnings.push({
      id: "WARN_PREDICTABLE_PATTERN",
      severity: "medium",
      message: "Predictable patterns (sequences, repeats, or keyboard walks) reduce practical resistance."
    });
  }
  if (yearSuffix) {
    warnings.push({
      id: "WARN_YEAR_SUFFIX",
      severity: "low",
      message: "Four-digit year patterns are routinely prioritized by credential attack tools."
    });
  }
  if (entropyInfo.warning === "ENTROPY_UNCALIBRATED_UNICODE") {
    warnings.push({
      id: "WARN_ENTROPY_UNCALIBRATED_UNICODE",
      severity: "info",
      message: "Theoretical entropy calculation is uncalibrated for non-ASCII Unicode characters."
    });
  }

  // Recommendations
  const recommendationIds = [];
  if (length < 12) recommendationIds.push("REC_INCREASE_LENGTH");
  else if (length < 15) recommendationIds.push("REC_CONSIDER_15_PLUS");

  if (isBundledExact || commonVariant || isCustomExact) {
    recommendationIds.push("REC_CHOOSE_UNRELATED_PHRASE");
  }
  if (sequenceCount > 0) recommendationIds.push("REC_REMOVE_SEQUENCES");
  if (repeatedRun) recommendationIds.push("REC_REMOVE_REPEATS");
  if (keyboardWalk) recommendationIds.push("REC_REMOVE_KEYBOARD_WALK");
  if (yearSuffix) recommendationIds.push("REC_REMOVE_YEAR");
  if (!hasUppercase || !hasLowercase) recommendationIds.push("REC_DIVERSIFY_CASING");
  if (!hasDigits) recommendationIds.push("REC_INCLUDE_DIGITS");
  if (!hasSymbols) recommendationIds.push("REC_INCLUDE_SYMBOLS");
  recommendationIds.push("REC_USE_PASSWORD_MANAGER");

  return {
    analysis_version: ANALYSIS_VERSION,
    score,
    classification,
    length_code_points: length,
    length_guidance: lengthGuidance,
    criteria: {
      length_target_met: lengthTargetMet,
      has_lowercase: hasLowercase,
      has_uppercase: hasUppercase,
      has_digits: hasDigits,
      has_symbols: hasSymbols
    },
    warnings,
    pattern_penalties: patternPenalties,
    entropy_estimate: entropyInfo,
    recommendation_ids: recommendationIds
  };
}

function generateAllowlistedExport(analysisResult, includeTimestamp = true) {
  const exportData = {
    report_schema_version: "2.0.0",
    analysis_version: analysisResult.analysis_version || ANALYSIS_VERSION
  };
  if (includeTimestamp) {
    exportData.generated_at = new Date().toISOString();
  }
  const allowlist = [
    "score",
    "classification",
    "length_code_points",
    "criteria",
    "warnings",
    "recommendation_ids",
    "entropy_estimate"
  ];
  for (const field of allowlist) {
    if (field in analysisResult) {
      exportData[field] = analysisResult[field];
    }
  }
  return exportData;
}

// Export for ES modules and Node.js test runner
export {
  ANALYSIS_VERSION,
  DEFAULT_BUNDLED_PASSWORDS,
  COMMON_BASES,
  KEYBOARD_WALK_PATTERNS,
  countCodePoints,
  detectSequences,
  detectRepeatedRuns,
  detectKeyboardWalks,
  detectYearSuffix,
  detectCommonVariant,
  calculateEntropy,
  analyzePassword,
  generateAllowlistedExport
};

// Global attachment for standard browser scripts
if (typeof window !== "undefined") {
  window.PasswordAnalyzer = {
    ANALYSIS_VERSION,
    DEFAULT_BUNDLED_PASSWORDS,
    COMMON_BASES,
    KEYBOARD_WALK_PATTERNS,
    countCodePoints,
    detectSequences,
    detectRepeatedRuns,
    detectKeyboardWalks,
    detectYearSuffix,
    detectCommonVariant,
    calculateEntropy,
    analyzePassword,
    generateAllowlistedExport
  };
}
