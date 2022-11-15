use crate::{
    Result,
    tests::TestPlan,
};

mod concatenated_armor;
mod mangled;

pub fn schedule(plan: &mut TestPlan) -> Result<()> {
    plan.add_section("ASCII Armor");
    plan.add(Box::new(concatenated_armor::ConcatenatedArmorKeyring::new()?));
    plan.add(Box::new(concatenated_armor::ConcatenatedArmorSignatures::new()?));
    plan.add(Box::new(mangled::MangledArmoredKey::new()?));
    plan.add(Box::new(mangled::MangledArmoredCert::new()?));
    plan.add(Box::new(mangled::MangledArmoredCiphertext::new()?));
    plan.add(Box::new(mangled::MangledArmoredSignature::new()?));
    Ok(())
}
