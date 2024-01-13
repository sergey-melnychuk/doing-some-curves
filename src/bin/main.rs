use doing_some_curves::{get_pk, sig, ver, get_pk_xy};
use sec1::EncodedPoint;
use generic_array::{typenum::U32, GenericArray};

fn main() {
    // let sk = doing_some_curves::rand();
    let sk = hex::decode("c5efb36bd2088906d47e324d29dbca4a1b0e1abc3bbb9353f311f10670348045").unwrap();
    let pk = get_pk(&sk);

    let msg = b"test";
    let (r, s) = sig(&sk, msg);
    let v = ver(&pk, msg, (&r, &s));

    {
        let (x, y) = get_pk_xy(&sk);
        println!("pk.x={}", hex::encode(&x));
        println!("pk.y={}", hex::encode(&y));
        let mut bytes = Vec::with_capacity(x.len() + y.len());
        bytes.extend_from_slice(&x);
        bytes.extend_from_slice(&y);
        let ga = GenericArray::from_iter(bytes.into_iter());
        let ep: EncodedPoint<U32> = EncodedPoint::from_untagged_bytes(&ga);
        let ep = ep.compress().as_bytes().to_vec();
        println!("  ep={}", hex::encode(&ep));
    };

    println!(
        "\nmsg={}\n sk={}\n pk={}\nsig={}{}\nval={v}",
        String::from_utf8(msg.to_vec()).unwrap(),
        hex::encode(&sk),
        hex::encode(&pk),
        hex::encode(&r),
        hex::encode(&s)
    )
}
