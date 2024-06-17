use crate::puzzles_info::{DataStoreInfo, DelegatedPuzzle};
use chia_protocol::CoinSpend;
use chia_sdk_driver::{InnerSpend, SpendContext, SpendError};
use clvm_traits::ToClvm;
use clvmr::NodePtr;

pub enum DatastoreInnerSpend {
    OwnerPuzzleSpend(InnerSpend),
    DelegatedPuzzleSpend(DelegatedPuzzle, InnerSpend),
}

pub fn datastore_spend<M>(
    ctx: &mut SpendContext<'_>,
    datastore_info: &DataStoreInfo<M>,
    inner_spend: DatastoreInnerSpend,
) -> Result<CoinSpend, SpendError>
where
    M: ToClvm<NodePtr>,
{
    // todo
}
