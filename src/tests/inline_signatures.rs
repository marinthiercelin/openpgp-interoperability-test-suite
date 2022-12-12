use crate::{
    Result,
    data,
    tests::TestPlan,
};

mod roundtrip;

pub fn schedule(plan: &mut TestPlan) -> Result<()> {
    plan.add_section("Inline Signatures");
    plan.add(Box::new(
        roundtrip::InlineSignVerifyRoundtrip::new(
            "Inline Sign-Verify roundtrip with key 'Alice'",
            "Inline Sign-Verify roundtrip using the 'Alice' key from \
             draft-bre-openpgp-samples-00.",
            data::certificate("alice-secret.pgp"),
            data::certificate("alice.pgp"),
            None, None,
            Some(Ok("Interoperability concern.".into())))?));
    plan.add(Box::new(
        roundtrip::InlineSignVerifyRoundtrip::new(
            "Sign+Encrypt-Decrypt+Verify roundtrip with key 'Alice'",
            "The signature is created using the 'Alice' key from \
             draft-bre-openpgp-samples-00, and the message is \
             encrypted for 'Bob'.",
            data::certificate("alice-secret.pgp"),
            data::certificate("alice.pgp"),
            data::certificate("bob-secret.pgp"),
            data::certificate("bob.pgp"),
            Some(Ok("Interoperability concern.".into())))?));

    plan.add(Box::new(
        roundtrip::InlineSignVerifyRoundtrip::new(
            "Inline Sign-Verify roundtrip with key 'Bob'",
            "Inline Sign-Verify roundtrip using the 'Bob' key from \
             draft-bre-openpgp-samples-00.",
            data::certificate("bob-secret.pgp"),
            data::certificate("bob.pgp"),
            None, None,
            Some(Ok("Interoperability concern.".into())))?));
    plan.add(Box::new(
        roundtrip::InlineSignVerifyRoundtrip::new(
            "Sign+Encrypt-Decrypt+Verify roundtrip with key 'Bob'",
            "The signature is created using the 'Bob' key from \
             draft-bre-openpgp-samples-00, and the message is \
             encrypted for 'Bob'.",
            data::certificate("bob-secret.pgp"),
            data::certificate("bob.pgp"),
            data::certificate("bob-secret.pgp"),
            data::certificate("bob.pgp"),
            Some(Ok("Interoperability concern.".into())))?));

    plan.add(Box::new(
        roundtrip::InlineSignVerifyRoundtrip::new(
            "Inline Sign-Verify roundtrip with key 'Carol'",
            "Inline Sign-Verify roundtrip using the 'Carol' key from \
             draft-bre-openpgp-samples-00.",
            data::certificate("carol-secret.pgp"),
            data::certificate("carol.pgp"),
            None, None,
            Some(Ok("Interoperability concern.".into())))?));
    plan.add(Box::new(
        roundtrip::InlineSignVerifyRoundtrip::new(
            "Sign+Encrypt-Decrypt+Verify roundtrip with key 'Carol'",
            "The signature is created using the 'Carol' key from \
             draft-bre-openpgp-samples-00, and the message is \
             encrypted for 'Bob'.",
            data::certificate("carol-secret.pgp"),
            data::certificate("carol.pgp"),
            data::certificate("bob-secret.pgp"),
            data::certificate("bob.pgp"),
            Some(Ok("Interoperability concern.".into())))?));

    plan.add(Box::new(
        roundtrip::InlineSignVerifyRoundtrip::new(
            "Inline Sign-Verify roundtrip with key 'John'",
            "This is an OpenPGP v3 key.",
            data::certificate("john-secret.pgp"),
            data::certificate("john.pgp"),
            None, None,
            None)?));
    plan.add(Box::new(
        roundtrip::InlineSignVerifyRoundtrip::new(
            "Sign+Encrypt-Decrypt+Verify roundtrip with key 'John'",
            "The signature is created using the v3 'John' key,
             and the message is encrypted for 'Bob'.",
            data::certificate("john-secret.pgp"),
            data::certificate("john.pgp"),
            data::certificate("bob-secret.pgp"),
            data::certificate("bob.pgp"),
            None)?));

    Ok(())
}
