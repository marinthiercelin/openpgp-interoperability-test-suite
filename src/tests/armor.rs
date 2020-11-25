use crate::{
    Result,
    templates::Report,
};

mod concatenated_armor;

pub fn schedule(report: &mut Report) -> Result<()> {
    report.add_section("ASCII Armor");
    report.add(Box::new(concatenated_armor::ConcatenatedArmorKeyring::new()?));
    Ok(())
}
