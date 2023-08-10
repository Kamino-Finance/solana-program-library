//! Feature gate CLI

use {
    clap::{crate_description, crate_name, crate_version, App, AppSettings, Arg, SubCommand},
    solana_clap_utils::{
        input_parsers::{keypair_of, pubkey_of},
        input_validators::{is_keypair, is_url, is_valid_pubkey, is_valid_signer},
    },
    solana_client::rpc_client::RpcClient,
    solana_sdk::{
        commitment_config::CommitmentConfig,
        feature::Feature,
        pubkey::Pubkey,
        rent::Rent,
        signature::{read_keypair_file, Keypair, Signer},
        system_instruction,
        transaction::Transaction,
    },
    spl_feature_gate::instruction::{activate, revoke},
};

#[allow(dead_code)]
struct Config {
    keypair: Box<dyn Signer>,
    json_rpc_url: String,
    verbose: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app_matches = App::new(crate_name!())
        .about(crate_description!())
        .version(crate_version!())
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .arg({
            let arg = Arg::with_name("config_file")
                .short("C")
                .long("config")
                .value_name("PATH")
                .takes_value(true)
                .global(true)
                .help("Configuration file to use");
            if let Some(ref config_file) = *solana_cli_config::CONFIG_FILE {
                arg.default_value(config_file)
            } else {
                arg
            }
        })
        .arg(
            Arg::with_name("keypair")
                .long("keypair")
                .value_name("KEYPAIR")
                .validator(is_valid_signer)
                .takes_value(true)
                .global(true)
                .help("Filepath or URL to a keypair [default: client keypair]"),
        )
        .arg(
            Arg::with_name("verbose")
                .long("verbose")
                .short("v")
                .takes_value(false)
                .global(true)
                .help("Show additional information"),
        )
        .arg(
            Arg::with_name("json_rpc_url")
                .long("url")
                .value_name("URL")
                .takes_value(true)
                .global(true)
                .validator(is_url)
                .help("JSON RPC URL for the cluster [default: value from configuration file]"),
        )
        .subcommand(
            SubCommand::with_name("activate")
                .about("Activate a feature")
                .arg(
                    Arg::with_name("feature_keypair")
                        .value_name("FEATURE_KEYPAIR")
                        .validator(is_keypair)
                        .index(1)
                        .required(true)
                        .help("Path to keypair of the feature"),
                ),
        )
        .subcommand(
            SubCommand::with_name("revoke")
                .about("Revoke a pending feature activation")
                .arg(
                    Arg::with_name("feature_keypair")
                        .value_name("FEATURE_KEYPAIR")
                        .validator(is_keypair)
                        .index(1)
                        .required(true)
                        .help("Path to keypair of the feature"),
                )
                .arg(
                    Arg::with_name("destination")
                        .value_name("DESTINATION")
                        .validator(is_valid_pubkey)
                        .index(2)
                        .required(true)
                        .help("The address of the destination for the refunded lamports"),
                ),
        )
        .get_matches();

    let (sub_command, sub_matches) = app_matches.subcommand();
    let matches = sub_matches.unwrap();

    let config = {
        let cli_config = if let Some(config_file) = matches.value_of("config_file") {
            solana_cli_config::Config::load(config_file).unwrap_or_default()
        } else {
            solana_cli_config::Config::default()
        };

        Config {
            json_rpc_url: matches
                .value_of("json_rpc_url")
                .unwrap_or(&cli_config.json_rpc_url)
                .to_string(),
            keypair: Box::new(read_keypair_file(
                matches
                    .value_of("keypair")
                    .unwrap_or(&cli_config.keypair_path),
            )?),
            verbose: matches.is_present("verbose"),
        }
    };
    solana_logger::setup_with_default("solana=info");
    let rpc_client =
        RpcClient::new_with_commitment(config.json_rpc_url.clone(), CommitmentConfig::confirmed());

    match (sub_command, sub_matches) {
        ("activate", Some(arg_matches)) => {
            let feature_keypair = keypair_of(arg_matches, "feature_keypair").unwrap();

            process_activate(&rpc_client, &config, &feature_keypair)
        }
        ("revoke", Some(arg_matches)) => {
            let feature_keypair = keypair_of(arg_matches, "feature_keypair").unwrap();
            let destination = pubkey_of(arg_matches, "destination").unwrap();

            process_revoke(&rpc_client, &config, &feature_keypair, &destination)
        }
        _ => unreachable!(),
    }
}

fn process_activate(
    rpc_client: &RpcClient,
    config: &Config,
    feature_keypair: &Keypair,
) -> Result<(), Box<dyn std::error::Error>> {
    println!();
    println!("Activating feature...");
    println!("Feature ID: {}", feature_keypair.pubkey());
    println!();
    println!("JSON RPC URL: {}", config.json_rpc_url);
    println!();

    let rent_lamports = Rent::default().minimum_balance(Feature::size_of());

    let transaction = Transaction::new_signed_with_payer(
        &[
            system_instruction::transfer(
                &config.keypair.pubkey(),
                &feature_keypair.pubkey(),
                rent_lamports,
            ),
            activate(&spl_feature_gate::id(), &feature_keypair.pubkey()),
        ],
        Some(&config.keypair.pubkey()),
        &[config.keypair.as_ref(), feature_keypair],
        rpc_client.get_latest_blockhash()?,
    );
    rpc_client.send_and_confirm_transaction_with_spinner(&transaction)?;

    println!();
    println!("Feature is marked for activation!");
    Ok(())
}

fn process_revoke(
    rpc_client: &RpcClient,
    config: &Config,
    feature_keypair: &Keypair,
    destination: &Pubkey,
) -> Result<(), Box<dyn std::error::Error>> {
    println!();
    println!("Revoking feature...");
    println!("Feature ID: {}", feature_keypair.pubkey());
    println!("Destination: {}", destination);
    println!();
    println!("JSON RPC URL: {}", config.json_rpc_url);
    println!();

    let transaction = Transaction::new_signed_with_payer(
        &[revoke(
            &spl_feature_gate::id(),
            &feature_keypair.pubkey(),
            destination,
        )],
        Some(&config.keypair.pubkey()),
        &[config.keypair.as_ref()],
        rpc_client.get_latest_blockhash()?,
    );
    rpc_client.send_and_confirm_transaction_with_spinner(&transaction)?;

    println!();
    println!("Feature successfully revoked!");
    Ok(())
}
