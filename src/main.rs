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
use std::env;

fn main() {

    let (iter_tx, iter_rx) = channel();
    let (done_tx, done_rx) = channel();
    let mut iters = 0i64;
    let stime = get_time().sec;

    let threads = 4;

    let hexstr = env::args().nth(1).unwrap();

    let mut byte = 0u8;
    let mut i = 0;
    let mut vec = Vec::new();
    for chr in hexstr.chars() {
        if i == 0 {
            if chr == '0' {
                i += 1;
                continue;
            } else {
                panic!("Invalid Hex String!");
            }
        }
        if i == 1 {
            if chr == 'x' {
                i += 1;
                continue;
            } else {
                panic!("Invalid Hex String!");
            }
        }
        byte += match chr.to_digit(16) {
            Some(num) => (num as u8) * match i % 2 {
                1 => 1,
                _ => 16
            },
            None => panic!("Invalid Hex String!")
        };
        if i % 2 == 1 {
            vec.push(byte);
            byte = 0;
        }
        i += 1;
    }
    let use_last_byte = if i % 2 == 1 {
        true
    } else {
        false
    };

    for _ in 0..threads {
        let iter_tx = iter_tx.clone();
        let done_tx = done_tx.clone();
        let vec = vec.clone();
        let last_byte = byte;
        thread::spawn(move || {

            let start = vec.as_slice();
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


                if res[12..].starts_with(start) && (!use_last_byte || (res[12+start.len()] >= last_byte && res[12+start.len()] <= last_byte + 15)) {
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
