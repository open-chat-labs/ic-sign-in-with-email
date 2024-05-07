use candid::Principal;
use canister_upgrader::{get_dfx_identity, upgrade_canister};
use clap::Parser;
use sign_in_with_email_canister::{AwsEmailSenderConfig, EmailSenderConfig};

#[tokio::main]
async fn main() {
    let opts = Opts::parse();

    let identity = get_dfx_identity(&opts.identity);

    upgrade_canister(
        identity,
        opts.ic_url,
        opts.canister_id,
        None,
        EmailSenderConfig::Aws(AwsEmailSenderConfig {
            region: opts.aws_region,
            function_url: opts.aws_function_url,
            access_key: opts.aws_access_key,
            secret_key: opts.aws_secret_key,
        }),
    )
    .await;
}

#[derive(Parser)]
struct Opts {
    #[arg(long)]
    identity: String,

    #[arg(long)]
    ic_url: String,

    #[arg(long)]
    canister_id: Principal,

    #[arg(long)]
    aws_region: String,

    #[arg(long)]
    aws_function_url: String,

    #[arg(long)]
    aws_access_key: String,

    #[arg(long)]
    aws_secret_key: String,
}
