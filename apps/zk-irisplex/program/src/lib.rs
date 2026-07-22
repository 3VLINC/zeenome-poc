//! IrisPlex Rust Implementation for zkEVM
//!
//! This module implements the IrisPlex eye color prediction algorithm
//! in a zkEVM-compatible way (no disk access, no std library).

use serde::{Deserialize, Serialize};

/// Error types for IrisPlex operations
#[derive(Debug, thiserror::Error)]
pub enum IrisPlexError {
    #[error("Invalid genotype: {0}")]
    InvalidGenotype(String),
    #[error("Missing variant at {0}:{1}")]
    MissingVariant(String, u32),
    #[error("Calculation error: {0}")]
    CalculationError(String),
    #[error("Merkle proof verification failed: {0}")]
    MerkleVerificationFailed(String),
    #[error("MMR proof verification failed: {0}")]
    MmrVerificationFailed(String),
}

use zeenome_core::snp::{Genotype, SnpData};

fn norm_chrom(c: &str) -> String {
    let t = c.trim();
    if t.len() >= 3 && t[..3].eq_ignore_ascii_case("chr") {
        format!("chr{}", &t[3..])
    } else {
        format!("chr{}", t)
    }
}

/// One marker: GRCh38 locus + IrisPlex minor allele (single-base panels).
#[derive(Debug, Clone)]
struct IrisMarker {
    chrom: &'static str,
    pos: u32,
    minor_allele: char,
    blue_weight: f64,
    brown_weight: f64,
}

fn find_variant<'a>(variants: &'a [SnpData], chrom: &str, pos: u32) -> Option<&'a SnpData> {
    let want = norm_chrom(chrom);
    variants
        .iter()
        .find(|v| norm_chrom(&v.chrom) == want && v.pos == pos)
}

fn first_base_upper(s: &str) -> Option<char> {
    s.chars().next().map(|c| c.to_ascii_uppercase())
}

/// Main IrisPlex calculator
pub struct IrisPlexCalculator {
    markers: Vec<IrisMarker>,
    constant_blue_weight: f64,
    constant_brown_weight: f64,
}

impl IrisPlexCalculator {
    /// Create a new IrisPlex calculator with IrisPlex coefficients (GRCh38 loci).
    pub fn new() -> Self {
        let markers = vec![
            IrisMarker {
                chrom: "chr15",
                pos: 28120472,
                minor_allele: 'A',
                blue_weight: -4.87,
                brown_weight: -1.99,
            },
            IrisMarker {
                chrom: "chr15",
                pos: 27985172,
                minor_allele: 'T',
                blue_weight: 1.15,
                brown_weight: 1.05,
            },
            IrisMarker {
                chrom: "chr14",
                pos: 92307319,
                minor_allele: 'G',
                blue_weight: -0.53,
                brown_weight: -0.01,
            },
            IrisMarker {
                chrom: "chr5",
                pos: 33951588,
                minor_allele: 'C',
                blue_weight: -1.53,
                brown_weight: -0.74,
            },
            IrisMarker {
                chrom: "chr11",
                pos: 89277878,
                minor_allele: 'A',
                blue_weight: 0.44,
                brown_weight: 0.26,
            },
            IrisMarker {
                chrom: "chr6",
                pos: 396321,
                minor_allele: 'T',
                blue_weight: 0.60,
                brown_weight: 0.69,
            },
        ];

        Self {
            markers,
            constant_blue_weight: 3.84,
            constant_brown_weight: 0.37,
        }
    }

    /// Predict eye color from verified normalized variants.
    pub fn predict(&self, variants: &[SnpData]) -> Result<IrisPlexResult, IrisPlexError> {
        let mut adjusted_blue_weight_sum = 0.0;
        let mut adjusted_brown_weight_sum = 0.0;

        for m in &self.markers {
            let snp = find_variant(variants, m.chrom, m.pos).ok_or_else(|| {
                IrisPlexError::MissingVariant(m.chrom.to_string(), m.pos)
            })?;

            let ref_char = first_base_upper(&snp.ref_allele).unwrap_or('N');
            let alt_char = first_base_upper(&snp.alt_allele).unwrap_or('N');
            let minor_char = m.minor_allele.to_ascii_uppercase();

            let multiplier = match snp.genotype {
                Genotype::HomozygousRef => {
                    if ref_char == minor_char {
                        2.0
                    } else {
                        0.0
                    }
                }
                Genotype::Heterozygous => {
                    (if ref_char == minor_char { 1.0 } else { 0.0 })
                        + (if alt_char == minor_char { 1.0 } else { 0.0 })
                }
                Genotype::HomozygousAlt => {
                    if alt_char == minor_char {
                        2.0
                    } else {
                        0.0
                    }
                }
                Genotype::Unknown => 0.0,
            };

            adjusted_blue_weight_sum += m.blue_weight * multiplier;
            adjusted_brown_weight_sum += m.brown_weight * multiplier;
        }

        let blue_log_weight = self.constant_blue_weight + adjusted_blue_weight_sum;
        let brown_log_weight = self.constant_brown_weight + adjusted_brown_weight_sum;
        let overall_blue_weight = blue_log_weight.exp();
        let overall_brown_weight = brown_log_weight.exp();

        let denominator = 1.0 + overall_blue_weight + overall_brown_weight;

        let blue_prob = overall_blue_weight / denominator;
        let intermediate_prob = overall_brown_weight / denominator;
        let brown_prob = 1.0 - blue_prob - intermediate_prob;

        let predicted_color = self.determine_eye_color(blue_prob, brown_prob, intermediate_prob);
        let confidence = self.calculate_confidence(blue_prob, brown_prob, intermediate_prob);

        Ok(IrisPlexResult {
            blue_probability: blue_prob,
            brown_probability: brown_prob,
            intermediate_probability: intermediate_prob,
            predicted_color,
            confidence,
        })
    }

    fn determine_eye_color(
        &self,
        blue_prob: f64,
        brown_prob: f64,
        intermediate_prob: f64,
    ) -> String {
        if blue_prob > brown_prob && blue_prob > intermediate_prob {
            "Blue".to_string()
        } else if brown_prob > blue_prob && brown_prob > intermediate_prob {
            "Brown".to_string()
        } else {
            "Intermediate".to_string()
        }
    }

    fn calculate_confidence(&self, blue_prob: f64, brown_prob: f64, intermediate_prob: f64) -> f64 {
        let max_prob = blue_prob.max(brown_prob).max(intermediate_prob);
        let second_max = if blue_prob == max_prob {
            brown_prob.max(intermediate_prob)
        } else if brown_prob == max_prob {
            blue_prob.max(intermediate_prob)
        } else {
            blue_prob.max(brown_prob)
        };

        max_prob - second_max
    }
}

impl Default for IrisPlexCalculator {
    fn default() -> Self {
        Self::new()
    }
}

/// IrisPlex prediction result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IrisPlexResult {
    pub blue_probability: f64,
    pub brown_probability: f64,
    pub intermediate_probability: f64,
    pub predicted_color: String,
    pub confidence: f64,
}
