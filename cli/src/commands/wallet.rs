use crate::config::EthrexL2Config;
use clap::Subcommand;
use ethertools_sdk::{
    balance_in_wei,
    client::{EthClient, Overrides},
    ethrex_l2::{
        deposit::deposit,
        withdraw::{claim_withdraw, get_withdraw_merkle_proof, withdraw},
    },
    transfer, wait_for_transaction_receipt,
};
use ethrex_common::{Address, Bytes, H256, U256};
use hex::FromHexError;

#[derive(Subcommand)]
pub(crate) enum Command {
    #[clap(about = "Get the balance of the wallet.")]
    Balance {
        #[clap(long = "token")]
        token_address: Option<Address>,
        #[arg(long = "l2", required = false)]
        l2: bool,
        #[arg(long = "l1", required = false)]
        l1: bool,
        #[arg(long = "wei", required = false, default_value_t = false)]
        wei: bool,
    },
    #[clap(about = "Deposit funds into some wallet.")]
    Deposit {
        // TODO: Parse ether instead.
        #[clap(long = "amount", value_parser = decode_u256)]
        amount: U256,
        #[clap(
            long = "token",
            help = "Specify the token address, the base token is used as default."
        )]
        token_address: Option<Address>,
        #[clap(
            long = "to",
            help = "Specify the wallet in which you want to deposit your funds."
        )]
        to: Option<Address>,
        #[clap(short = 'w', required = false)]
        wait_for_receipt: bool,
        #[clap(long, short = 'e', required = false)]
        explorer_url: bool,
    },
    #[clap(about = "Finalize a pending withdrawal.")]
    ClaimWithdraw {
        l2_withdrawal_tx_hash: H256,
        #[clap(short = 'w', required = false)]
        wait_for_receipt: bool,
    },
    #[clap(about = "Transfer funds to another wallet.")]
    Transfer {
        // TODO: Parse ether instead.
        #[clap(long = "amount", value_parser = decode_u256)]
        amount: U256,
        #[clap(long = "token")]
        token_address: Option<Address>,
        #[clap(long = "to")]
        to: Address,
        #[clap(long = "nonce")]
        nonce: Option<u64>,
        #[clap(short = 'w', required = false)]
        wait_for_receipt: bool,
        #[clap(
            long = "l1",
            required = false,
            help = "If set it will do an L1 transfer, defaults to an L2 transfer"
        )]
        l1: bool,
        #[clap(long, short = 'e', required = false)]
        explorer_url: bool,
    },
    #[clap(about = "Withdraw funds from the wallet.")]
    Withdraw {
        // TODO: Parse ether instead.
        #[clap(long = "amount", value_parser = decode_u256)]
        amount: U256,
        #[clap(long = "nonce")]
        nonce: Option<u64>,
        #[clap(
            long = "token",
            help = "Specify the token address, the base token is used as default."
        )]
        token_address: Option<Address>,
        #[clap(short = 'w', required = false)]
        wait_for_receipt: bool,
        #[clap(long, short = 'e', required = false)]
        explorer_url: bool,
    },
    #[clap(about = "Get the withdrawal merkle proof of a transaction.")]
    WithdrawalProof {
        #[clap(long = "hash")]
        tx_hash: H256,
    },
    #[clap(about = "Get the wallet address.")]
    Address,
    #[clap(about = "Get the wallet private key.")]
    PrivateKey,
    #[clap(about = "Send a transaction")]
    Send {
        #[clap(long = "to")]
        to: Address,
        #[clap(
            long = "value",
            value_parser = decode_u256,
            default_value = "0",
            required = false,
            help = "Value to send in wei"
        )]
        value: U256,
        #[clap(long = "calldata", value_parser = decode_hex, required = false, default_value = "")]
        calldata: Bytes,
        #[clap(
            long = "l1",
            required = false,
            help = "If set it will do an L1 transfer, defaults to an L2 transfer"
        )]
        l1: bool,
        #[clap(long = "chain-id", required = false)]
        chain_id: Option<u64>,
        #[clap(long = "nonce", required = false)]
        nonce: Option<u64>,
        #[clap(long = "gas-limit", required = false)]
        gas_limit: Option<u64>,
        #[clap(long = "gas-price", required = false)]
        max_fee_per_gas: Option<u64>,
        #[clap(long = "priority-gas-price", required = false)]
        max_priority_fee_per_gas: Option<u64>,
        #[clap(short = 'w', required = false)]
        wait_for_receipt: bool,
    },
    #[clap(about = "Make a call to a contract")]
    Call {
        #[clap(long = "to")]
        to: Address,
        #[clap(long = "calldata", value_parser = decode_hex, required = false, default_value = "")]
        calldata: Bytes,
        #[clap(
            long = "l1",
            required = false,
            help = "If set it will do an L1 transfer, defaults to an L2 transfer"
        )]
        l1: bool,
        #[clap(
            long = "value",
            value_parser = decode_u256,
            default_value = "0",
            required = false,
            help = "Value to send in wei"
        )]
        value: U256,
        #[clap(long = "from", required = false)]
        from: Option<Address>,
        #[clap(long = "gas-limit", required = false)]
        gas_limit: Option<u64>,
        #[clap(long = "gas-price", required = false)]
        max_fee_per_gas: Option<u64>,
    },
    #[clap(about = "Deploy a contract")]
    Deploy {
        #[clap(long = "bytecode", value_parser = decode_hex)]
        bytecode: Bytes,
        #[clap(
            long = "l1",
            required = false,
            help = "If set it will do an L1 transfer, defaults to an L2 transfer"
        )]
        l1: bool,
        #[clap(
            long = "value",
            value_parser = decode_u256,
            default_value = "0",
            required = false,
            help = "Value to send in wei"
        )]
        value: U256,
        #[clap(long = "chain-id", required = false)]
        chain_id: Option<u64>,
        #[clap(long = "nonce", required = false)]
        nonce: Option<u64>,
        #[clap(long = "gas-limit", required = false)]
        gas_limit: Option<u64>,
        #[clap(long = "gas-price", required = false)]
        max_fee_per_gas: Option<u64>,
        #[clap(long = "priority-gas-price", required = false)]
        max_priority_fee_per_gas: Option<u64>,
        #[clap(short = 'w', required = false)]
        wait_for_receipt: bool,
    },
}

fn decode_hex(s: &str) -> Result<Bytes, FromHexError> {
    match s.strip_prefix("0x") {
        Some(s) => hex::decode(s).map(Into::into),
        None => hex::decode(s).map(Into::into),
    }
}

impl Command {
    pub async fn run(self, cfg: EthrexL2Config) -> eyre::Result<()> {
        let eth_client = EthClient::new(&cfg.network.l1_rpc_url);
        let rollup_client = EthClient::new(&cfg.network.l2_rpc_url);
        let from = cfg.wallet.address;
        match self {
            Command::Balance {
                token_address,
                l2,
                l1,
                wei,
            } => {
                if token_address.is_some() {
                    todo!("Handle ERC20 balances")
                }
                if !l1 || l2 {
                    let account_balance = rollup_client.get_balance(from).await?;
                    println!(
                        "[L2] Account balance: {}",
                        balance_in_wei(wei, account_balance)
                    );
                }
                if l1 {
                    let account_balance = eth_client.get_balance(from).await?;
                    println!(
                        "[L1] Account balance: {}",
                        balance_in_wei(wei, account_balance)
                    );
                }
            }
            Command::Deposit {
                amount,
                token_address,
                to,
                wait_for_receipt,
                explorer_url: _,
            } => {
                if to.is_some() {
                    // There are two ways of depositing funds into the L2:
                    // 1. Directly transferring funds to the bridge.
                    // 2. Depositing through a contract call to the deposit method of the bridge.
                    // The second method is not handled in the CLI yet.
                    todo!("Handle deposits through contract")
                }

                if token_address.is_some() {
                    todo!("Handle ERC20 deposits")
                }

                let tx_hash = deposit(
                    amount,
                    cfg.wallet.address,
                    cfg.wallet.private_key,
                    &eth_client,
                    Overrides::default(),
                )
                .await?;

                println!("Deposit sent: {tx_hash:#x}");

                if wait_for_receipt {
                    wait_for_transaction_receipt(&eth_client, tx_hash).await?;
                }
            }
            Command::ClaimWithdraw {
                l2_withdrawal_tx_hash,
                wait_for_receipt,
            } => {
                let tx_hash = claim_withdraw(
                    l2_withdrawal_tx_hash,
                    U256::default(),
                    cfg.wallet.address,
                    cfg.wallet.private_key,
                    &rollup_client,
                    &eth_client,
                )
                .await?;

                println!("Withdrawal claim sent: {tx_hash:#x}");

                if wait_for_receipt {
                    wait_for_transaction_receipt(&eth_client, tx_hash).await?;
                }
            }
            Command::Transfer {
                amount,
                token_address,
                to,
                nonce,
                wait_for_receipt,
                l1,
                explorer_url: _,
            } => {
                if token_address.is_some() {
                    todo!("Handle ERC20 transfers")
                }

                let client = if l1 { eth_client } else { rollup_client };

                let tx_hash = transfer(
                    amount,
                    cfg.wallet.address,
                    to,
                    cfg.wallet.private_key,
                    &client,
                    Overrides {
                        value: Some(amount),
                        nonce,
                        ..Default::default()
                    },
                )
                .await?;

                println!(
                    "[{}] Transfer sent: {tx_hash:#x}",
                    if l1 { "L1" } else { "L2" }
                );

                if wait_for_receipt {
                    wait_for_transaction_receipt(&client, tx_hash).await?;
                }
            }
            Command::Withdraw {
                amount,
                nonce,
                token_address: _,
                wait_for_receipt,
                explorer_url: _,
            } => {
                let tx_hash = withdraw(
                    amount,
                    cfg.wallet.address,
                    cfg.wallet.private_key,
                    &rollup_client,
                    nonce,
                )
                .await?;

                println!("Withdrawal sent: {tx_hash:#x}");

                if wait_for_receipt {
                    wait_for_transaction_receipt(&rollup_client, tx_hash).await?;
                }
            }
            Command::WithdrawalProof { tx_hash } => {
                let (_index, path) = get_withdraw_merkle_proof(&rollup_client, tx_hash).await?;
                println!("{path:?}");
            }
            Command::Address => {
                println!("{:#x}", cfg.wallet.address);
            }
            Command::PrivateKey => {
                println!("0x{}", hex::encode(cfg.wallet.private_key.secret_bytes()));
            }
            Command::Send {
                to,
                value,
                calldata,
                l1,
                chain_id,
                nonce,
                gas_limit,
                max_fee_per_gas,
                max_priority_fee_per_gas,
                wait_for_receipt,
            } => {
                let client = if l1 { eth_client } else { rollup_client };

                let tx = client
                    .build_eip1559_transaction(
                        to,
                        cfg.wallet.address,
                        calldata,
                        Overrides {
                            value: Some(value),
                            chain_id: if let Some(chain_id) = chain_id {
                                Some(chain_id)
                            } else if l1 {
                                Some(cfg.network.l1_chain_id)
                            } else {
                                Some(cfg.network.l2_chain_id)
                            },
                            nonce,
                            gas_limit,
                            max_fee_per_gas,
                            max_priority_fee_per_gas,
                            from: Some(cfg.wallet.address),
                            ..Default::default()
                        },
                        10,
                    )
                    .await?;
                let tx_hash = client
                    .send_eip1559_transaction(&tx, &cfg.wallet.private_key)
                    .await?;

                println!(
                    "[{}] Transaction sent: {tx_hash:#x}",
                    if l1 { "L1" } else { "L2" }
                );

                if wait_for_receipt {
                    wait_for_transaction_receipt(&client, tx_hash).await?;
                }
            }
            Command::Call {
                to,
                calldata,
                l1,
                value,
                from,
                gas_limit,
                max_fee_per_gas,
            } => {
                let client = match l1 {
                    true => eth_client,
                    false => rollup_client,
                };

                let result = client
                    .call(
                        to,
                        calldata,
                        Overrides {
                            from,
                            value: value.into(),
                            gas_limit,
                            max_fee_per_gas,
                            ..Default::default()
                        },
                    )
                    .await?;

                println!("{result}");
            }
            Command::Deploy {
                bytecode,
                l1,
                value,
                chain_id,
                nonce,
                gas_limit,
                max_fee_per_gas,
                max_priority_fee_per_gas,
                wait_for_receipt,
            } => {
                let client = match l1 {
                    true => eth_client,
                    false => rollup_client,
                };

                let (deployment_tx_hash, deployed_contract_address) = client
                    .deploy(
                        from,
                        cfg.wallet.private_key,
                        bytecode,
                        Overrides {
                            value: value.into(),
                            nonce,
                            chain_id,
                            gas_limit,
                            max_fee_per_gas,
                            max_priority_fee_per_gas,
                            ..Default::default()
                        },
                    )
                    .await?;

                println!("Contract deployed in tx: {deployment_tx_hash:#x}");
                println!("Contract address: {deployed_contract_address:#x}");

                if wait_for_receipt {
                    wait_for_transaction_receipt(&client, deployment_tx_hash).await?;
                }
            }
        };
        Ok(())
    }
}
