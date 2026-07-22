/// Commitment messages for signed lineage (genomic VCF + phenotype), unified
/// with an explicit domain tag so collisions cannot occur across domains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactDomain {
    GenomicVcf,
    Phenotype,
}

fn domain_tag(domain: ArtifactDomain) -> &'static str {
    match domain {
        ArtifactDomain::GenomicVcf => "GENOMIC",
        ArtifactDomain::Phenotype => "PHENOTYPE",
    }
}

#[must_use]
pub fn commitment_message(
    domain: ArtifactDomain,
    actor_id: &str,
    data_merkle_root: &str,
    epoch_number: i32,
    epoch_root: &str,
    registry_root: &str,
) -> Vec<u8> {
    format!(
        "{}|{}|{}|{}|{}|{}",
        domain_tag(domain),
        actor_id,
        data_merkle_root,
        epoch_number,
        epoch_root,
        registry_root
    )
    .into_bytes()
}
