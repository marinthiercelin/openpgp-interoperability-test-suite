/// This program creates improbable short RSA signatures by brute
/// force.

use std::env;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::Context;
use sequoia_openpgp as openpgp;
use openpgp::{
    crypto::*,
    parse::Parse,
    serialize::{
        Serialize,
        stream::{Armorer, Message},
    },
    policy::StandardPolicy as P,
    types::*,
    packet::prelude::*,
};

/// How many threads to spawn.
const WORKER_THREADS: usize = 20;

/// Message used in tests.
///
/// For consistency, all tests that sign/encrypt a message should use
/// this statement.
pub const MESSAGE: &[u8] = b"Hello World :)";

/// This keeps track of the shortest generated signature.
static SHORTEST: AtomicUsize = AtomicUsize::new(usize::MAX);

fn main() -> openpgp::Result<()> {
    let p = &P::new();
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        return Err(anyhow::anyhow!("Usage: {} <secret-keyfile>\n", args[0]));
    }

    // Read the transferable secret keys from the given files.
    let mut keys = Vec::new();
    for filename in &args[1..] {
        let tsk = openpgp::Cert::from_file(filename)
            .context("Failed to read key")?;
        let mut n = 0;

        for key in tsk
            .keys().with_policy(p, None).alive().revoked(false).for_signing().secret()
            .map(|ka| ka.key())
        {
            keys.push({
                let key = key.clone();
                n += 1;
                key.into_keypair()?
            });
        }

        if n == 0 {
            return Err(anyhow::anyhow!("Found no suitable signing key on {}", tsk));
        }
    }
    let signer = keys.pop().unwrap();

    fn worker(mut signer: openpgp::crypto::KeyPair) {
        loop {
            let sig = SignatureBuilder::new(SignatureType::Binary)
                .sign_message(&mut signer, MESSAGE).unwrap();

            let bits = if let mpi::Signature::RSA { s } = sig.mpis() {
                s.bits()
            } else {
                unreachable!()
            };

            if SHORTEST.fetch_min(bits, Ordering::Relaxed) > bits {
                eprintln!("New shortest sig: {} bits", bits);

                // Compose a writer stack corresponding to the output format and
                // packet structure we want.
                let mut sink = std::fs::File::create(format!("{}-bit.sig", bits))
                    .unwrap();

                // Stream an OpenPGP message.
                let message = Message::new(&mut sink);
                let mut message = Armorer::new(message)
                    .kind(openpgp::armor::Kind::Signature)
                    .build().unwrap();
                Packet::from(sig).serialize(&mut message).unwrap();
                message.finalize().unwrap();
            }
        }
    }

    for _ in 0..WORKER_THREADS - 1 {
        let signer = signer.clone();
        std::thread::spawn(|| worker(signer));
    }
    worker(signer);

    Ok(())
}

