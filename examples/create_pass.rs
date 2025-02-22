#![allow(unused_imports)]

extern crate passkit;
extern crate serde_json;

use passkit::{
    Barcode, BarcodeFormat, Field, Location, PassBuilder, PassSource, TransitType, Value,
};

use std::error::Error;
use std::fs;

fn main() {
    let pass = PassBuilder::new("0001", "pass.it.cinemapedagna.tkt", "5BW43H5V5J")
        .web_service(
            "vxwxd7J8AlNNFPS8k0a0FfUFtq0ewzFdc",
            "https://example.com/passes/",
        )
        .relevant_date("2018-11-25T14:25-08:00".into())
        .add_location((-122.3748889, 37.6189722))
        .add_barcode((BarcodeFormat::Code128, "FOOBAR BAZBAF 193197"))
        .organization_name("Surface Lines")
        .description("Surface Lines Pass")
        .logo_text("Surface Lines")
        .add_header_field(("gate", "GATE", "23"))
        .add_header_field(("example", "EXAM", 22))
        .finish_boarding_pass(TransitType::Train);

    // println!("{}", serde_json::to_string_pretty(&pass).unwrap());

    let mut source = PassSource::new(
        "examples/BoardingPass.pass/",
        include_bytes!(env!("PASS_CERTIFICATE")).as_slice(),
        include_bytes!(env!("PASS_KEY")).as_slice(),
        "",
    );

    let pass = source.build_pkpass(Some(pass)).expect("Example failed");
    std::fs::write("test.pkpass", pass).expect("Could not save pkpass file");

    // println!("{:#?}", source);
}
