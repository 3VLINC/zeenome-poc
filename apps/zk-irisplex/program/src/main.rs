//! SP1 program wrapper for IrisPlex prediction.
#![no_main]
sp1_zkvm::entrypoint!(main);

use zeenome_core::snp::{
    assert_panel_targets_present, GenomeBuild, IRISPLEX_TARGET_SNPS,
};
use zeenome_core::zk::{
    commit_public_output_with_policy, payload_status_ineligible, read_and_verify_inputs,
};
use zk_irisplex_program::{IrisPlexCalculator, IrisPlexResult};

pub fn main() {
    let verified_inputs =
        read_and_verify_inputs().expect("Failed to read and verify inputs");

    let merkle_root = verified_inputs
        .snp_merkle_root
        .clone()
        .unwrap_or_else(|| verified_inputs.json_merkle_root.clone().unwrap_or_default());

    let snps = verified_inputs.snps.expect("SNP data is required for IrisPlex prediction");

    if assert_panel_targets_present(&snps, IRISPLEX_TARGET_SNPS, GenomeBuild::GRCh38).is_err() {
        commit_public_output_with_policy(
            &verified_inputs.policy,
            &verified_inputs.job_id,
            &merkle_root,
            payload_status_ineligible("missing_panel_targets"),
        );
        return;
    }

    let calc = IrisPlexCalculator::new();
    let result: IrisPlexResult = calc.predict(&snps).expect("IrisPlex prediction failed");

    let payload = format!(
        "blue_probability:{}\nbrown_probability:{}\nintermediate_probability:{}\npredicted_color:{}\nconfidence:{}",
        result.blue_probability,
        result.brown_probability,
        result.intermediate_probability,
        result.predicted_color,
        result.confidence
    );

    commit_public_output_with_policy(
        &verified_inputs.policy,
        &verified_inputs.job_id,
        &merkle_root,
        payload,
    );
}
