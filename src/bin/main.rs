use doing_some_curves::{get_pk, get_pk_xy, sig, ver};

fn main() {
    // let sk = doing_some_curves::rand();
    let sk =
        hex::decode("c5efb36bd2088906d47e324d29dbca4a1b0e1abc3bbb9353f311f10670348045").unwrap();
    let pk = get_pk(&sk);

    let msg = b"test";
    let (mut r, mut s) = sig(&sk, msg);
    r.reverse();
    s.reverse();
    println!(
        " pk={}\nsig:\n  r={}\n  s={}",
        hex::encode(&pk),
        hex::encode(&r),
        hex::encode(&s),
    );
    let v = ver(&pk, msg, (&r, &s));

    let pk = {
        println!();
        use generic_array::{typenum::U32, GenericArray};
        use sec1::EncodedPoint;

        let xy = get_pk_xy(&sk);
        let ga = GenericArray::from_iter(xy.into_iter());
        let ep: EncodedPoint<U32> = EncodedPoint::from_untagged_bytes(&ga);
        let ep = ep.compress().as_bytes().to_vec();
        println!("  ep={}", hex::encode(&ep));
        println!();
        ep
    };

    println!(
        "msg={}\n sk={}\n pk={}\nsig={}{}\nval={v}",
        String::from_utf8(msg.to_vec()).unwrap(),
        hex::encode(&sk),
        hex::encode(&pk),
        hex::encode(&r),
        hex::encode(&s)
    )
}
