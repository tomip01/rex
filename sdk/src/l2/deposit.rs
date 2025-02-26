use crate::{
    client::{EthClient, EthClientError, Overrides},
    transfer,
};
use ethrex_common::{Address, H256, U256};
use secp256k1::SecretKey;

pub async fn deposit(
    amount: U256,
    from: Address,
    from_pk: SecretKey,
    eth_client: &EthClient,
    bridge_address: Address,
    mut overrides: Overrides,
) -> Result<H256, EthClientError> {
    overrides.value = Some(amount);
    transfer(amount, from, bridge_address, from_pk, eth_client, overrides).await
}
