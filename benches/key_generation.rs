use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::thread_rng;
use yggdrasil_keys::NodeIdentity;

fn generate_keys(c: &mut Criterion) {
    let mut rng = thread_rng();
    c.bench_function("generate_key", |b| {
        b.iter(|| {
            let node = NodeIdentity::new(&mut rng);
            let leading_ones = node.strength();
            black_box(leading_ones);
        })
    });
}

criterion_group!(benches, generate_keys);
criterion_main!(benches);
