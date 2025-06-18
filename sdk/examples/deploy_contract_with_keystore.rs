use ethrex_rpc::EthClient;
use rex_sdk::keystore::{create_new_keystore, load_keystore_from_path};

//Habría que codear un contrato de ejemplo en solidity
// con una función que recupere al signer dado un mensaje y una firma y lo emita en un log

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a keystore.
    create_new_keystore(None, Some("ContractKeystore"), "LambdaClass")?;
    // Load the private key from the keystore.
    let private_key = load_keystore_from_path(None, "ContractKeystore", "LambdaClass")?;

    // Connect the client to a node
    let mut client = EthClient::new("127.0.0.1:8545");

    // Deploy a contract.

    // Get the current block (for later).

    // Prepare the calldata to call the contract function that emits a log.

    // Call the contract signing with the private key and wait for its receipt.

    // Get the new current block.

    // Get the emitted logs using the current block and the previous current block.

    Ok(())
}
