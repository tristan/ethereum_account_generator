extern crate tiny_keccak;
extern crate rand;
extern crate secp256k1;
extern crate time;

use std::thread;
use tiny_keccak::Keccak;
use rand::thread_rng;
use secp256k1::key::{SecretKey, PublicKey};
use secp256k1::Secp256k1;
use time::get_time;
use std::fmt::Write;
use std::sync::mpsc::channel;

fn main() {

    let (iter_tx, iter_rx) = channel();
    let (done_tx, done_rx) = channel();
    let mut iters = 0i64;
    let stime = get_time().sec;

    let threads = 4;

    for _ in 0..threads {
        let iter_tx = iter_tx.clone();
        let done_tx = done_tx.clone();
        thread::spawn(move || {

            let context = Secp256k1::new();

            let mut rng = thread_rng();

            loop {

                let mut sha3 = Keccak::new_keccak256();

                let privkey = SecretKey::new(&context, &mut rng);

                let pubkey = PublicKey::from_secret_key(&context, &privkey).unwrap();

                let pubkeydata = &pubkey.serialize_vec(&context, false);

                sha3.update(&pubkeydata[1..]);
                let mut res: [u8; 32] = [0; 32];
                sha3.finalize(&mut res);

                if res[12] == 0x7E && res[13] == 0x57 && res[14] == 0 {
                    let mut s = String::new();
                    write!(&mut s, "Private Key: 0x").unwrap();
                    for &byte in &privkey[..] {
                        write!(&mut s, "{:02X}", byte).unwrap();
                    }
                    write!(&mut s, "\nAddress: 0x").unwrap();
                    for &byte in &res[12..] {
                        write!(&mut s, "{:02X}", byte).unwrap();
                    }
                    done_tx.send(s).unwrap();
                    match iter_tx.send(1) {
                        Ok(_) => {}
                        Err(_) => break
                    }
                    break;
                } else {
                    match iter_tx.send(1) {
                        Ok(_) => {}
                        Err(_) => break
                    }
                }

            }
        });
    }

    loop {
        for _ in 0..threads {
            iters += iter_rx.recv().unwrap();
        }
        let mut ntime = get_time().sec - stime;
        if ntime == 0 {
            ntime = 1;
        }
        print!("Attemps: {}. Average rate: {} attempts/second            \r", iters, iters / ntime);
        match done_rx.try_recv() {
            Ok(s) => {
                println!("\n{}", s);
                break;
            }
            Err(_) => {}
        }
    }

}
