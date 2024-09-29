use anyhow::Context;
use clap::Parser;
use frost_ed25519::{self as frost, keys::{IdentifierList, SecretShare}, Ed25519ScalarField, Field, Identifier};
use iroh_net::key::PublicKey;
use rand::thread_rng;
use sha2::{Digest, Sha512};
use std::{any, collections::BTreeMap, path::PathBuf, str::FromStr};

#[derive(Debug, clap::Parser)]
struct Args {
    #[clap(subcommand)]
    cmd: Command,
}

#[derive(Debug, clap::Parser)]
enum Command {
    Split(SplitArgs),
    Reconstruct(ReconstructArgs),
}

#[derive(Debug, clap::Parser)]
struct SplitArgs {
    /// nodes that are going to own the shares
    nodes: Vec<String>,
    #[clap(long, help = "threshold for the secret sharing. Default is n-1. Must be less than the number of nodes, and greater than 1.")]
    threshold: Option<u16>,
    /// Key to split
    #[clap(long)]
    key: PathBuf,
}

#[derive(Debug, clap::Parser)]
struct ReconstructArgs {
    directories: Vec<String>,
    #[clap(long)]
    name: String,
    #[clap(long)]
    message: String,
    #[clap(long)]
    key: Option<PublicKey>,
}

fn split(args: SplitArgs) -> anyhow::Result<()> {
    let identifiers = args.nodes.iter().map(|node| {
        Identifier::derive(node.as_bytes()).context("unable to derive identifier")
    }).collect::<anyhow::Result<Vec<_>>>()?;
    let max_signers: u16 = args.nodes.len().try_into().context("too many nodes")?;
    let min_signers = args.threshold.unwrap_or(max_signers - 1);
    let key = std::fs::read_to_string(&args.key)?;
    let iroh_key = iroh_net::key::SecretKey::try_from_openssh(&key)?;
    let key_bytes = iroh_key.to_bytes();
    let scalar = ed25519_secret_key_to_scalar(&key_bytes);
    let key = frost::SigningKey::from_scalar(scalar);
    let (parts, pubkey) = frost::keys::split(&key, max_signers, min_signers, IdentifierList::Custom(&identifiers), &mut thread_rng())?;
    let pubkey_bytes = postcard::to_allocvec(&pubkey).context("unable to serialize pubkey")?;
    for (node, id) in args.nodes.iter().zip(identifiers.iter()) {
        let secret_share = parts.get(id).context("missing part")?;
        let path: PathBuf = format!("{}", node).into();
        std::fs::create_dir_all(&path)?;
        let pubkey_path = path.join(format!("{}.pub", iroh_key.public()));
        std::fs::write(pubkey_path, &pubkey_bytes)?;
        let key_path = path.join(format!("{}.secret", iroh_key.public()));
        let secret_share_bytes = secret_share.serialize()?;
        std::fs::write(key_path, secret_share_bytes)?;
    }
    Ok(())
}

fn reconstruct(args: ReconstructArgs) -> anyhow::Result<()> {
    let mut parts = Vec::new();
    let mut paths = Vec::new();
    for part in args.directories.iter() {
        let secret_share_path = PathBuf::from(part).join(format!("{}.secret", args.name));
        let secret_share_bytes = std::fs::read(&secret_share_path)?;
        paths.push(secret_share_path);
        let secret_share = SecretShare::deserialize(&secret_share_bytes)?;
        let key_package = frost::keys::KeyPackage::try_from(secret_share)?;
        parts.push(key_package);
    }
    let secret = frost::keys::reconstruct(parts.as_slice())?;
    println!("Reconstructed a signing key from {:?}", paths);
    let signature = secret.sign(rand::thread_rng(), args.message.as_bytes());
    let signature_bytes = signature.serialize();
    println!("Signature: {:?}", hex::encode(&signature_bytes));
    if let Some(key) = args.key {
        let iroh_signature: iroh_net::key::Signature = signature_bytes.into();
        let res = key.verify(args.message.as_bytes(), &iroh_signature);
        println!("Verification: {:?}", res);
    }
    Ok(())
}

fn ed25519_secret_key_to_scalar(secret_key: &[u8; 32]) -> <Ed25519ScalarField as Field>::Scalar {
    // Step 1: Hash the secret key using SHA-512
    let mut hasher = Sha512::new();
    hasher.update(secret_key);
    let hash = hasher.finalize();

    // Step 2: Take the first 32 bytes of the hash and apply bit manipulations
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(&hash[..32]);

    // Step 3: Perform bitwise manipulations to ensure it's a valid scalar
    scalar_bytes[0] &= 248; // Clear the lowest 3 bits
    scalar_bytes[31] &= 127; // Clear the highest bit
    scalar_bytes[31] |= 64;  // Set the second highest bit

    // Step 4: Create the Scalar from the modified bytes
    <Ed25519ScalarField as Field>::Scalar::from_bytes_mod_order(scalar_bytes)
}
 
fn main() -> anyhow::Result<()> {

    let args = Args::parse();
    match args.cmd {
        Command::Split(args) => split(args)?,
        Command::Reconstruct(args) => reconstruct(args)?,
    }
    return Ok(());

    let mut rng = thread_rng();
    let max_signers = 5;
    let min_signers = 3;
    let (shares, pubkey_package) = frost::keys::generate_with_dealer(
        max_signers,
        min_signers,
        frost::keys::IdentifierList::Default,
        &mut rng,
    )?;

    // Verifies the secret shares from the dealer and store them in a BTreeMap.
    // In practice, the KeyPackages must be sent to its respective participants
    // through a confidential and authenticated channel.
    let mut key_packages: BTreeMap<_, _> = BTreeMap::new();

    for (identifier, secret_share) in shares {
        let key_package = frost::keys::KeyPackage::try_from(secret_share)?;
        key_packages.insert(identifier, key_package);
    }
    println!("Key packages generated successfully!");
    for (k, v) in key_packages.iter() {
        println!("Key package for participant {:?}: {:?}", k, v);
    }

    let mut nonces_map = BTreeMap::new();
    let mut commitments_map = BTreeMap::new();

    ////////////////////////////////////////////////////////////////////////////
    // Round 1: generating nonces and signing commitments for each participant
    ////////////////////////////////////////////////////////////////////////////

    // In practice, each iteration of this loop will be executed by its respective participant.
    for participant_index in 1..(min_signers as u16 + 1) {
        let participant_identifier = participant_index.try_into().expect("should be nonzero");
        let key_package = &key_packages[&participant_identifier];
        // Generate one (1) nonce and one SigningCommitments instance for each
        // participant, up to _threshold_.
        let (nonces, commitments) = frost::round1::commit(
            key_packages[&participant_identifier].signing_share(),
            &mut rng,
        );
        // In practice, the nonces must be kept by the participant to use in the
        // next round, while the commitment must be sent to the coordinator
        // (or to every other participant if there is no coordinator) using
        // an authenticated channel.
        nonces_map.insert(participant_identifier, nonces);
        commitments_map.insert(participant_identifier, commitments);
    }

    // This is what the signature aggregator / coordinator needs to do:
    // - decide what message to sign
    // - take one (unused) commitment per signing participant
    let mut signature_shares = BTreeMap::new();
    let message = "message to sign".as_bytes();
    let signing_package = frost::SigningPackage::new(commitments_map, message);

    ////////////////////////////////////////////////////////////////////////////
    // Round 2: each participant generates their signature share
    ////////////////////////////////////////////////////////////////////////////

    // In practice, each iteration of this loop will be executed by its respective participant.
    for participant_identifier in nonces_map.keys() {
        let key_package = &key_packages[participant_identifier];

        let nonces = &nonces_map[participant_identifier];

        // Each participant generates their signature share.
        let signature_share = frost::round2::sign(&signing_package, nonces, key_package)?;

        // In practice, the signature share must be sent to the Coordinator
        // using an authenticated channel.
        signature_shares.insert(*participant_identifier, signature_share);
    }

    ////////////////////////////////////////////////////////////////////////////
    // Aggregation: collects the signing shares from all participants,
    // generates the final signature.
    ////////////////////////////////////////////////////////////////////////////

    // Aggregate (also verifies the signature shares)
    let group_signature = frost::aggregate(&signing_package, &signature_shares, &pubkey_package)?;

    // Check that the threshold signature can be verified by the group public
    // key (the verification key).
    let is_signature_valid = pubkey_package
        .verifying_key()
        .verify(message, &group_signature)
        .is_ok();
    assert!(is_signature_valid);
    Ok(())
}
