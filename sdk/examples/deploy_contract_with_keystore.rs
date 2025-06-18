use ethrex_common::{H160, H256};
use rex_sdk::client::EthClient;
use rex_sdk::client::eth::get_address_from_secret_key;
use rex_sdk::{
    keystore::{create_new_keystore, load_keystore_from_path},
    sign::sign_hash,
};

const RPC_URL: &str = "https://ethereum-holesky-rpc.publicnode.com";

//Habría que codear un contrato de ejemplo en solidity
// con una función que recupere al signer dado un mensaje y una firma y lo emita en un log

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a keystore.
    create_new_keystore(None, Some("ContractKeystore"), "LambdaClass")?;

    // Load the private key from the keystore.
    let private_key = load_keystore_from_path(None, "ContractKeystore", "LambdaClass")?;

    // Connect the client to a node
    let client = EthClient::new(RPC_URL);

    // Get address from private key
    let address = get_address_from_secret_key(&private_key)?;

    // Deploy a contract.
    client.deploy(address, private_key, init_code, overrides);

    // Get the current block (for later).
    let from_block = client.get_block_number().await?;

    // Prepare the calldata to call the contract function that emits a log.
    let _msg = sign_hash(H256::random(), private_key);

    // Call the contract signing with the private key and wait for its receipt.
    //client.call();

    // Get the new current block.
    let to_block = client.get_block_number().await?;

    // Get the emitted logs using the current block and the previous current block.
    let logs = client
        .get_logs_from_signature(from_block, to_block, H160::zero(), "dsadasdas")
        .await?;

    println!("Logs: {:?}", logs);

    Ok(())
}
