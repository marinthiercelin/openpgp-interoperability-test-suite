use crate::{
    Result,
    plan::TestPlan,
};

mod concatenated_armor;
mod mangled;

pub fn schedule(plan: &mut TestPlan) -> Result<()> {
    plan.add_section("ASCII Armor");
    plan.add(Box::new(concatenated_armor::ConcatenatedArmorKeyring::new()?));
    plan.add(Box::new(mangled::MangledArmor::new()?));
    Ok(())
}
