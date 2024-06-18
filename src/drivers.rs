use crate::{
    puzzles_info::{DataStoreInfo, DelegatedPuzzle},
    DelegationLayerArgs, ADMIN_FILTER_PUZZLE, ADMIN_FILTER_PUZZLE_HASH, DELEGATION_LAYER_PUZZLE,
    DELEGATION_LAYER_PUZZLE_HASH, WRITER_FILTER_PUZZLE, WRITER_FILTER_PUZZLE_HASH,
};
use chia::consensus::merkle_tree::MerkleSet;
use chia_protocol::CoinSpend;
use chia_sdk_driver::{
    spend_nft_state_layer, spend_singleton, InnerSpend, SpendContext, SpendError,
};
use clvm_traits::ToClvm;
use clvm_utils::CurriedProgram;
use clvmr::{reduction::EvalErr, Allocator, NodePtr};

pub trait SpendContextExt {
    fn delegation_layer_puzzle(&mut self) -> Result<NodePtr, SpendError>;
    fn delegated_admin_filter(&mut self) -> Result<NodePtr, SpendError>;
    fn delegated_writer_filter(&mut self) -> Result<NodePtr, SpendError>;
}

impl<'a> SpendContextExt for SpendContext<'a> {
    fn delegation_layer_puzzle(&mut self) -> Result<NodePtr, SpendError> {
        self.puzzle(DELEGATION_LAYER_PUZZLE_HASH, &DELEGATION_LAYER_PUZZLE)
    }

    fn delegated_admin_filter(&mut self) -> Result<NodePtr, SpendError> {
        self.puzzle(ADMIN_FILTER_PUZZLE_HASH, &ADMIN_FILTER_PUZZLE)
    }

    fn delegated_writer_filter(&mut self) -> Result<NodePtr, SpendError> {
        self.puzzle(WRITER_FILTER_PUZZLE_HASH, &WRITER_FILTER_PUZZLE)
    }
}

pub enum DatastoreInnerSpend {
    OwnerPuzzleSpend(InnerSpend),
    DelegatedPuzzleSpend(DelegatedPuzzle, InnerSpend),
}

pub fn datastore_spend<M>(
    ctx: &mut SpendContext<'_>,
    datastore_info: &DataStoreInfo<M>,
    inner_datastore_spend: DatastoreInnerSpend,
) -> Result<CoinSpend, SpendError>
where
    M: ToClvm<NodePtr>,
{
    // 1. Handle delegation layer spend
    let inner_spend: Result<InnerSpend, SpendError> = match datastore_info.delegated_puzzle_hashes {
        None => match inner_datastore_spend {
            DatastoreInnerSpend::OwnerPuzzleSpend(inner_spend) => Ok(inner_spend),
            DatastoreInnerSpend::DelegatedPuzzleSpend(_, inner_spend) => {
                Err(SpendError::Eval(EvalErr(
                    inner_spend.puzzle(),
                    String::from("data store does not have a delegation layer"),
                )))
            }
        },
        Some(delegated_puzzle_hashes) => {
            let mut leafs: Vec<[u8; 32]> = delegated_puzzle_hashes
                .iter()
                .map(|hash| -> [u8; 32] {
                    match hash {
                        // todo
                        _ => [0; 32],
                    }
                })
                .collect();
            let merkle_set = MerkleSet::from_leafs(&mut leafs);
            let merkle_root: [u8; 32] = merkle_set.get_root();

            let new_inner_puzzle_mod = ctx.delegation_layer_puzzle()?;
            let new_inner_puzzle_args = DelegationLayerArgs::new(merkle_root.into());

            let new_inner_puzzle = CurriedProgram {
                program: new_inner_puzzle_mod,
                args: new_inner_puzzle_args,
            };

            let new_inner_solution = match inner_datastore_spend {
                DatastoreInnerSpend::OwnerPuzzleSpend(_) => {
                    unimplemented!("todo")
                }
                DatastoreInnerSpend::DelegatedPuzzleSpend(delegated_puzzle, _) => {
                    let delegated_puzzle = match delegated_puzzle {
                        DelegatedPuzzle::Admin(_) => ctx.delegated_admin_filter()?,
                        DelegatedPuzzle::Writer(_) => ctx.delegated_writer_filter()?,
                        DelegatedPuzzle::Oracle(_) => {
                            return Err(SpendError::Eval(EvalErr(
                                new_inner_puzzle.to_clvm(ctx.allocator())?,
                                String::from("data store does not have a delegation layer"),
                            )))
                        }
                    };
                    CurriedProgram {
                        program: delegated_puzzle,
                        args: new_inner_puzzle.to_clvm(ctx.allocator())?,
                    }
                }
            };

            let a = &mut Allocator::new();
            Ok(InnerSpend {
                puzzle: new_inner_puzzle.to_clvm(a)?,
                solution: unimplemented!("todo"),
            })
        }
    };
    let inner_spend = inner_spend?;

    // 2. Handle state layer spend
    let state_layer_spend = spend_nft_state_layer(ctx, &datastore_info.metadata, inner_spend)?;

    // 3. Spend singleton
    spend_singleton(
        ctx,
        datastore_info.coin,
        datastore_info.launcher_id,
        datastore_info.proof,
        state_layer_spend,
    )
}
