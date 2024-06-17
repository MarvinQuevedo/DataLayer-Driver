use crate::{
    puzzles_info::{DataStoreInfo, DelegatedPuzzle},
    DELEGATION_LAYER_PUZZLE, DELEGATION_LAYER_PUZZLE_HASH,
};
use chia_protocol::CoinSpend;
use chia_sdk_driver::{InnerSpend, SpendContext, SpendError};
use clvm_traits::ToClvm;
use clvmr::NodePtr;

pub trait SpendContextExt {
    fn delegation_layer_puzzle(&mut self) -> Result<NodePtr, SpendError>;
    // fn delegated_admin_filter(&mut self) -> Result<NodePtr, SpendError>;
    // fn delegated_writer_filter(&mut self) -> Result<NodePtr, SpendError>;
}

impl<'a> SpendContextExt for SpendContext<'a> {
    fn delegation_layer_puzzle(&mut self) -> Result<NodePtr, SpendError> {
        self.puzzle(DELEGATION_LAYER_PUZZLE_HASH, &DELEGATION_LAYER_PUZZLE)
    }
}

pub enum DatastoreInnerSpend {
    OwnerPuzzleSpend(InnerSpend),
    DelegatedPuzzleSpend(DelegatedPuzzle, InnerSpend),
}

// pub fn datastore_spend<M>(
//     ctx: &mut SpendContext<'_>,
//     datastore_info: &DataStoreInfo<M>,
//     inner_spend: DatastoreInnerSpend,
// ) -> Result<CoinSpend, SpendError>
// where
//     M: ToClvm<NodePtr>,
// {
//     // todo
// }
