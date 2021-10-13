use criterion::{criterion_group, criterion_main, Criterion};
use mast::Mast;
use rand::rngs::OsRng;
use schnorrkel::{
    musig::{aggregate_public_key_from_slice, AggregatePublicKey},
    Keypair, PublicKey,
};

fn generate_pubkey(num: usize) -> Vec<PublicKey> {
    let mut pubkeys = Vec::new();
    for _ in 0..num {
        let keypair: Keypair = Keypair::generate_with(OsRng);
        pubkeys.push(keypair.public);
    }
    pubkeys
}

fn get_agg_pubkey(pubkeys: &Vec<PublicKey>, threshold: usize) -> PublicKey {
    let mut agg_pubkeys = Vec::new();
    for i in 0..threshold {
        agg_pubkeys.push(pubkeys[i].clone())
    }
    aggregate_public_key_from_slice(agg_pubkeys.as_mut_slice())
        .unwrap()
        .public_key()
}

fn bench_generate_merkle_proof(
    pubkeys: Vec<PublicKey>,
    threshold: usize,
    agg_pubkey: PublicKey,
) -> Vec<u8> {
    let mast = Mast::new(pubkeys, threshold).unwrap();
    let proof = mast.generate_merkle_proof(&agg_pubkey).unwrap();
    proof
}

fn criterion_benchmark(c: &mut Criterion) {
    let pubkeys = generate_pubkey(5);
    let pubkey = get_agg_pubkey(&pubkeys, 3);

    c.bench_function("[pubkeys num]: 5 [threshold]: 3", |b| {
        b.iter(|| bench_generate_merkle_proof(pubkeys.clone(), 3, pubkey.clone()))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
