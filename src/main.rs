use anyhow::Context;
use clap::Parser;
use frost_ed25519::{
    self as frost,
    keys::{IdentifierList, SecretShare},
    Ed25519ScalarField, Field, Identifier,
};
use iroh_net::key::PublicKey;
use rand::thread_rng;
use sha2::{Digest, Sha512};
use std::{collections::BTreeMap, path::PathBuf, str::FromStr};

#[derive(Debug, clap::Parser)]
struct Args {
    #[clap(subcommand)]
    cmd: Command,
}

#[derive(Debug, clap::Parser)]
enum Command {
    Split(SplitArgs),
    Sign(SignArgs),
    Cosign(CosignArgs),
}

#[derive(Debug, clap::Parser)]
struct SplitArgs {
    /// nodes that are going to own the shares
    nodes: Vec<String>,
    #[clap(
        long,
        help = "threshold for the secret sharing. Default is n-1. Must be less than the number of nodes, and greater than 1."
    )]
    threshold: Option<u16>,
    /// Key to split
    #[clap(long)]
    key: PathBuf,
}

#[derive(Debug, clap::Parser)]
struct SignArgs {
    directories: Vec<String>,
    #[clap(long)]
    message: String,
    #[clap(long)]
    key: PublicKey,
}

#[derive(Debug, clap::Parser)]
struct CosignArgs {
    /// Optional path to the directory where the fragments are stored
    #[clap(long)]
    data_path: Option<PathBuf>,
}

fn split(args: SplitArgs) -> anyhow::Result<()> {
    let identifiers = args
        .nodes
        .iter()
        .map(|node| Identifier::derive(node.as_bytes()).context("unable to derive identifier"))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let max_signers: u16 = args.nodes.len().try_into().context("too many nodes")?;
    let min_signers = args.threshold.unwrap_or(max_signers - 1);
    let key = std::fs::read_to_string(&args.key)?;
    let iroh_key = iroh_net::key::SecretKey::try_from_openssh(&key)?;
    let key_bytes = iroh_key.to_bytes();
    let scalar = ed25519_secret_key_to_scalar(&key_bytes);
    let key = frost::SigningKey::from_scalar(scalar);
    let (parts, pubkey) = frost::keys::split(
        &key,
        max_signers,
        min_signers,
        IdentifierList::Custom(&identifiers),
        &mut thread_rng(),
    )?;
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

fn sign(args: SignArgs) -> anyhow::Result<()> {
    let mut parts = Vec::new();
    let mut paths = Vec::new();
    let key = args.key;
    for part in args.directories.iter() {
        let secret_share_path = PathBuf::from(part).join(format!("{}.secret", key));
        let secret_share_bytes = std::fs::read(&secret_share_path)?;
        paths.push(secret_share_path);
        let secret_share = SecretShare::deserialize(&secret_share_bytes)?;
        let key_package = frost::keys::KeyPackage::try_from(secret_share)?;
        parts.push(key_package);
    }
    let secret = frost::keys::reconstruct(parts.as_slice())?;
    println!("Reconstructed a signing key from {:?}", paths);
    let msg = args.message.as_bytes();
    let signature = secret.sign(rand::thread_rng(), msg);
    let signature_bytes = signature.serialize();
    println!("Signature: {}", hex::encode(&signature_bytes));
    let iroh_signature: iroh_net::key::Signature = signature_bytes.into();
    let res = key.verify(msg, &iroh_signature);
    if res.is_err() {
        println!("Verification failed: {:?}", res);
        res?;
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
    scalar_bytes[31] |= 64; // Set the second highest bit

    // Step 4: Create the Scalar from the modified bytes
    <Ed25519ScalarField as Field>::Scalar::from_bytes_mod_order(scalar_bytes)
}

async fn handle_cosign_request(
    incoming: iroh_net::endpoint::Incoming,
    data_path: PathBuf,
) -> anyhow::Result<()> {
    let mut connecting = incoming.accept()?;
    let alpn = connecting.alpn().await?;
    let connection = connecting.await?;
    let remote_node_id = iroh_net::endpoint::get_remote_node_id(&connection)?;
    tracing::info!(
        "Incoming connection from {} (ALPN {})",
        remote_node_id,
        std::str::from_utf8(&alpn)?
    );
    let (mut send, mut recv) = connection.accept_bi().await?;
    let mut key = [0u8; 32];
    recv.read_exact(&mut key).await?;
    let key = PublicKey::from_bytes(&key)?;
    tracing::info!("Received request to co-sign for key {}", key);
    let secret_share_path = data_path.join(format!("{}.secret", key));
    let secret_share_bytes = std::fs::read(&secret_share_path)?;
    let secret_share = SecretShare::deserialize(&secret_share_bytes)?;
    let key_package = frost::keys::KeyPackage::try_from(secret_share)?;
    tracing::info!("Got fragment, creating commitment");
    let (nonces, commitments) =
        frost::round1::commit(key_package.signing_share(), &mut thread_rng());
    let commitments_bytes = commitments.serialize()?;
    let commitments_bytes_len = commitments_bytes.len() as u32;
    tracing::info!("Sending commitment");
    send.write_all(&commitments_bytes_len.to_be_bytes()).await?;
    send.write_all(&commitments_bytes).await?;
    tracing::info!("Waiting for signing package");
    let mut signing_package_len_bytes = [0u8; 4];
    recv.read_exact(&mut signing_package_len_bytes).await?;
    let mut signing_package_bytes =
        vec![0u8; u32::from_be_bytes(signing_package_len_bytes) as usize];
    recv.read_exact(&mut signing_package_bytes).await?;
    let signing_package = frost::SigningPackage::deserialize(&signing_package_bytes)?;
    tracing::info!("Received signing package, creating signature share");
    let signature_share = frost::round2::sign(&signing_package, &nonces, &key_package)?;
    let signature_share_bytes = signature_share.serialize();
    tracing::info!("Sending signature share");
    send.write_all(&signature_share_bytes).await?;
    send.finish()?;
    Ok(())
}

async fn cosign_daemon(args: CosignArgs) -> anyhow::Result<()> {
    let data_path = args.data_path.unwrap_or_else(|| PathBuf::from("."));
    let mut keys = Vec::new();
    for entry in std::fs::read_dir(&data_path)? {
        let entry = entry?;
        let path = entry.path();
        if path
            .extension()
            .map(|ext| ext == "secret")
            .unwrap_or_default()
        {
            if let Some(stem) = path.file_stem() {
                if let Some(text) = stem.to_str() {
                    let key = iroh_net::key::PublicKey::from_str(text)?;
                    let secret_share_bytes = std::fs::read(&path)?;
                    let secret_share = SecretShare::deserialize(&secret_share_bytes)?;
                    let key_package = frost::keys::KeyPackage::try_from(secret_share)?;
                    keys.push((key, key_package));
                }
            }
        }
    }
    if !keys.is_empty() {
        println!("Can cosign for following keys");
        for (key, key_package) in keys.iter() {
            println!("- {} (min {} signers)", key, key_package.min_signers());
            println!("{:?}", key_package.identifier())
        }
    }
    let endpoint = iroh_net::endpoint::Endpoint::builder()
        .alpns(vec![b"FROST_COSIGN".to_vec()])
        .bind()
        .await?;
    let addr = endpoint.node_addr().await?;
    println!("Listening on {}", addr.node_id);
    while let Some(incoming) = endpoint.accept().await {
        let data_path = data_path.clone();
        tokio::task::spawn(async {
            if let Err(cause) = handle_cosign_request(incoming, data_path).await {
                tracing::error!("Error handling cosign request: {:?}", cause);
            }
        });
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    match args.cmd {
        Command::Split(args) => split(args)?,
        Command::Sign(args) => sign(args)?,
        Command::Cosign(args) => cosign_daemon(args).await?,
    }
    Ok(())
}

/// Example copied from the frost docs
fn example() -> anyhow::Result<()> {
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
        let (nonces, commitments) = frost::round1::commit(key_package.signing_share(), &mut rng);
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
