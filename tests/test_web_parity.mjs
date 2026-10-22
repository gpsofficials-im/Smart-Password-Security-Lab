/**
 * Automated Parity Test Suite for Smart Password Security Lab.
 *
 * Verifies that the JavaScript engine (assets/js/analyzer.js) matches
 * the Python engine's outputs on 100% of the golden test vectors.
 *
 * Run with: node --test tests/test_web_parity.mjs
 */

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  analyzePassword,
  countCodePoints,
  calculateEntropy,
  DEFAULT_BUNDLED_PASSWORDS
} from "../assets/js/analyzer.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const goldenVectorsPath = path.join(__dirname, "golden_vectors.json");
const goldenVectors = JSON.parse(fs.readFileSync(goldenVectorsPath, "utf-8"));

test("JavaScript Analyzer Parity against Golden Vectors", async (t) => {
  for (const vector of goldenVectors) {
    await t.test(`Vector [${vector.id}]: ${vector.description}`, () => {
      const customSet = vector.custom_dict && vector.custom_dict.length > 0
        ? new Set(vector.custom_dict.map((w) => w.toLowerCase()))
        : null;

      const result = analyzePassword(vector.password, customSet, DEFAULT_BUNDLED_PASSWORDS);
      const expected = vector.expected;

      // Assert Score and Classification
      assert.equal(
        result.score,
        expected.score,
        `Score mismatch for '${vector.id}': expected ${expected.score}, got ${result.score}`
      );

      assert.equal(
        result.classification,
        expected.classification,
        `Classification mismatch for '${vector.id}': expected ${expected.classification}, got ${result.classification}`
      );

      // Assert Unicode code points count
      assert.equal(
        result.length_code_points,
        expected.length_code_points,
        `Code point count mismatch for '${vector.id}'`
      );

      // Assert Core Criteria
      assert.deepEqual(
        result.criteria,
        expected.criteria,
        `Criteria mismatch for '${vector.id}'`
      );

      // Assert Entropy Status & Warnings
      assert.equal(
        result.entropy_estimate.status,
        expected.entropy_status,
        `Entropy status mismatch for '${vector.id}'`
      );

      assert.equal(
        result.entropy_estimate.warning,
        expected.entropy_warning,
        `Entropy warning mismatch for '${vector.id}'`
      );

      // Assert Rule IDs detected in penalties
      const actualRuleIds = result.pattern_penalties.map((p) => p.rule_id);
      assert.deepEqual(
        actualRuleIds,
        expected.rule_ids,
        `Rule IDs mismatch for '${vector.id}': expected ${JSON.stringify(expected.rule_ids)}, got ${JSON.stringify(actualRuleIds)}`
      );

      // Assert Warning IDs
      const actualWarningIds = result.warnings.map((w) => w.id);
      assert.deepEqual(
        actualWarningIds,
        expected.warning_ids,
        `Warning IDs mismatch for '${vector.id}'`
      );

      // Assert Recommendation IDs
      assert.deepEqual(
        result.recommendation_ids,
        expected.recommendation_ids,
        `Recommendation IDs mismatch for '${vector.id}'`
      );
    });
  }
});
