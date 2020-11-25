use crate::{
    Result,
    templates::Report,
};

mod concatenated_armor;
mod mangled;

pub fn schedule(report: &mut Report) -> Result<()> {
    report.add_section("ASCII Armor");
    report.add(Box::new(concatenated_armor::ConcatenatedArmorKeyring::new()?));
    report.add(Box::new(mangled::MangledArmor::new()?));
    Ok(())
}
