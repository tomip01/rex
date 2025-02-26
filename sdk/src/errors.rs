use crate::client::EthClientError;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    EthClientError(#[from] EthClientError),
}
