use bytes::{Buf, BufMut, Bytes, BytesMut};
use clap::{Parser, Subcommand};
use commonware_codec::{Encode, EncodeSize, Error, Read, ReadExt, Write};
use commonware_consensus::{
    simplex::{
        scheme::bls12381_threshold::vrf as threshold_vrf,
        types::{Finalization, Finalize, Notarization, Notarize, Proposal},
    },
    types::{Epoch, Height, Round, View},
    Block as ConsensusBlock, CertifiableBlock, Heightable, Viewable,
};
use commonware_cryptography::{
    bls12381::{
        dkg::feldman_desmedt::deal,
        primitives::{sharing::Mode, variant::MinSig},
    },
    ed25519, sha256, Digest as _, Digestible, Hasher, Sha256, Signer,
};
use commonware_math::algebra::Random;
use commonware_parallel::Sequential;
use commonware_utils::{ordered::Set, N3f1};
use exoware_sdk::{StoreClient, StoreWriteBatch};
use exoware_simplex::{encode_block_data, keys, Finalized, Notarized, SimplexClient};
use rand::{rngs::StdRng, SeedableRng};
use tracing::info;

const DEMO_NAMESPACE: &[u8] = b"_EXOWARE_SIMPLEX_DEMO";
const DEMO_FIXTURE_SEED: u64 = 7;
const DEMO_PARTICIPANTS: u32 = 4;
const SCHEME: &str = "bls12381-threshold-vrf-min-sig";

type Scheme = threshold_vrf::Scheme<ed25519::PublicKey, MinSig>;
type Sha256Digest = sha256::Digest;
type Context = commonware_consensus::simplex::types::Context<Sha256Digest, ed25519::PublicKey>;

#[derive(Parser, Debug)]
#[command(name = "simplex", version, about = "Simplex sandbox utilities.")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Seed {
        #[arg(long)]
        store_url: String,
        #[arg(long, default_value_t = 2)]
        interval_secs: u64,
        #[arg(long)]
        start_height: Option<u64>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DemoBlock {
    context: Context,
    parent: Sha256Digest,
    height: Height,
    payload: Vec<u8>,
    digest: Sha256Digest,
}

impl DemoBlock {
    fn new(
        height: u64,
        parent_view: View,
        parent_digest: Sha256Digest,
        body_digest: Sha256Digest,
        leader: ed25519::PublicKey,
    ) -> Self {
        let context = Context {
            round: Round::new(Epoch::zero(), View::new(height)),
            leader,
            parent: (parent_view, parent_digest),
        };
        let mut block = Self {
            context,
            parent: parent_digest,
            height: Height::new(height),
            payload: body_digest.as_ref().to_vec(),
            digest: Sha256Digest::EMPTY,
        };
        block.digest = block.compute_digest();
        block
    }

    fn compute_digest(&self) -> Sha256Digest {
        let mut header = BytesMut::with_capacity(self.encode_size());
        self.write(&mut header);
        let mut hasher = Sha256::new();
        hasher.update(&header);
        hasher.finalize()
    }
}

impl Write for DemoBlock {
    fn write(&self, buf: &mut impl BufMut) {
        self.context.write(buf);
        self.parent.write(buf);
        self.height.write(buf);
        self.payload.write(buf);
    }
}

impl Read for DemoBlock {
    type Cfg = usize;

    fn read_cfg(buf: &mut impl Buf, max_payload_len: &Self::Cfg) -> Result<Self, Error> {
        let context = Context::read(buf)?;
        let parent = Sha256Digest::read(buf)?;
        let height = Height::read(buf)?;
        let payload = Vec::<u8>::read_cfg(buf, &((..=*max_payload_len).into(), ()))?;
        let mut block = Self {
            context,
            parent,
            height,
            payload,
            digest: Sha256Digest::EMPTY,
        };
        block.digest = block.compute_digest();
        Ok(block)
    }
}

impl EncodeSize for DemoBlock {
    fn encode_size(&self) -> usize {
        self.context.encode_size()
            + self.parent.encode_size()
            + self.height.encode_size()
            + self.payload.encode_size()
    }
}

impl Digestible for DemoBlock {
    type Digest = Sha256Digest;

    fn digest(&self) -> Self::Digest {
        self.digest
    }
}

impl Heightable for DemoBlock {
    fn height(&self) -> Height {
        self.height
    }
}

impl ConsensusBlock for DemoBlock {
    fn parent(&self) -> Self::Digest {
        self.parent
    }
}

impl CertifiableBlock for DemoBlock {
    type Context = Context;

    fn context(&self) -> Self::Context {
        self.context.clone()
    }
}

fn demo_schemes() -> Vec<Scheme> {
    let mut rng = StdRng::seed_from_u64(DEMO_FIXTURE_SEED);
    let private_keys: Vec<_> = (0..DEMO_PARTICIPANTS)
        .map(|_| ed25519::PrivateKey::random(&mut rng))
        .collect();
    let participants = Set::from_iter_dedup(
        private_keys
            .iter()
            .map(|private_key| private_key.public_key()),
    );
    let (output, shares) = deal::<MinSig, _, N3f1>(&mut rng, Mode::default(), participants.clone())
        .expect("demo threshold DKG should succeed");
    let polynomial = output.public().clone();
    shares
        .into_iter()
        .map(|(_, share)| {
            threshold_vrf::Scheme::signer(
                DEMO_NAMESPACE,
                participants.clone(),
                polynomial.clone(),
                share,
            )
            .expect("demo threshold signer should be a participant")
        })
        .collect()
}

fn proposal(block: &DemoBlock) -> Proposal<Sha256Digest> {
    Proposal::new(block.context.round, block.context.parent.0, block.digest())
}

fn notarized(block: DemoBlock, schemes: &[Scheme]) -> Notarized<DemoBlock, Scheme, Sha256Digest> {
    let proposal = proposal(&block);
    let votes: Vec<_> = schemes
        .iter()
        .map(|scheme| Notarize::sign(scheme, proposal.clone()).expect("notarize"))
        .collect();
    let proof =
        Notarization::from_notarizes(&schemes[0], &votes, &Sequential).expect("notarization");
    Notarized::new(proof, block).expect("notarized")
}

fn finalized(block: DemoBlock, schemes: &[Scheme]) -> Finalized<DemoBlock, Scheme, Sha256Digest> {
    let proposal = proposal(&block);
    let votes: Vec<_> = schemes
        .iter()
        .map(|scheme| Finalize::sign(scheme, proposal.clone()).expect("finalize"))
        .collect();
    let proof =
        Finalization::from_finalizes(&schemes[0], &votes, &Sequential).expect("finalization");
    Finalized::new(proof, block).expect("finalized")
}

async fn upload_certificates(
    client: &SimplexClient,
    notarized: &Notarized<DemoBlock, Scheme, Sha256Digest>,
    finalized: &Finalized<DemoBlock, Scheme, Sha256Digest>,
    body: &[u8],
) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
    let header = finalized.header.encode();
    let block = encode_block_data(&finalized.header, body);
    let notarized_bytes = notarized.encode();
    let finalized_bytes = finalized.encode();
    let mut batch = StoreWriteBatch::new();
    batch.push(
        client.store_client(),
        &keys::header_by_digest(&finalized.header.digest()),
        header,
    )?;
    batch.push(
        client.store_client(),
        &keys::block_by_digest(&finalized.header.digest()),
        block,
    )?;
    batch.push(
        client.store_client(),
        &keys::notarization_by_view(notarized.proof.view()),
        notarized_bytes,
    )?;
    batch.push(
        client.store_client(),
        &keys::finalization_by_view(finalized.proof.view()),
        finalized_bytes.clone(),
    )?;
    batch.push(
        client.store_client(),
        &keys::finalized_by_height(finalized.header.height()),
        finalized_bytes,
    )?;
    Ok(batch.commit(client.store_client()).await?)
}

async fn seed(
    store_url: &str,
    interval_secs: u64,
    start_height: Option<u64>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!(store_url, interval_secs, "starting simplex seed");

    let client = SimplexClient::new(StoreClient::new(store_url));
    let schemes = demo_schemes();
    let verification_material = schemes[0].identity().encode().to_vec();
    let leader = schemes
        .first()
        .and_then(|scheme| scheme.participants().iter().next().cloned())
        .expect("demo fixture has a leader");

    println!("simplex seed verifier");
    println!("scheme={SCHEME}");
    println!(
        "namespace_utf8={}",
        std::str::from_utf8(DEMO_NAMESPACE).expect("demo namespace is utf-8")
    );
    println!("namespace_hex=0x{}", hex::encode(DEMO_NAMESPACE));
    println!(
        "verification_material=0x{}",
        hex::encode(&verification_material)
    );

    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let mut height = start_height.unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock must be after unix epoch")
            .as_secs()
            .max(1)
    });
    let mut parent_view = View::new(height.saturating_sub(1));
    let mut parent_digest = Sha256Digest::EMPTY;

    loop {
        tokio::select! {
            biased;
            _ = tokio::signal::ctrl_c() => {
                info!("ctrl-c received, shutting down");
                break;
            }
            _ = ticker.tick() => {}
        }

        let body = Bytes::from(format!("simplex-demo-block-body-{height}").into_bytes());
        let body_digest = Sha256::hash(&body);
        let block = DemoBlock::new(
            height,
            parent_view,
            parent_digest,
            body_digest,
            leader.clone(),
        );
        let notarized = notarized(block.clone(), &schemes);
        let finalized = finalized(block.clone(), &schemes);
        let sequence = upload_certificates(&client, &notarized, &finalized, &body).await?;

        println!(
            "sequence={} view={} height={} digest=0x{}",
            sequence,
            finalized.proof.view().get(),
            finalized.header.height().get(),
            hex::encode(finalized.header.digest().encode()),
        );

        parent_view = finalized.proof.view();
        parent_digest = finalized.header.digest();
        height = height.saturating_add(1);
    }

    Ok(())
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .try_init();
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    init_tracing();
    let cli = Cli::parse();

    let result = match cli.command {
        Command::Seed {
            store_url,
            interval_secs,
            start_height,
        } => seed(&store_url, interval_secs, start_height).await,
    };

    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("simplex failed: {err}");
            std::process::ExitCode::FAILURE
        }
    }
}
