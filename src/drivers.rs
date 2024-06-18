use crate::{
    puzzles_info::{DataStoreInfo, DelegatedPuzzle},
    DelegationLayerArgs, DelegationLayerSolution, ADMIN_FILTER_PUZZLE, ADMIN_FILTER_PUZZLE_HASH,
    DELEGATION_LAYER_PUZZLE, DELEGATION_LAYER_PUZZLE_HASH, WRITER_FILTER_PUZZLE,
    WRITER_FILTER_PUZZLE_HASH,
};
use chia::consensus::{
    gen::opcodes::{CREATE_COIN, CREATE_PUZZLE_ANNOUNCEMENT},
    merkle_tree::MerkleSet,
};
use chia_protocol::{Bytes32, CoinSpend};
use chia_sdk_driver::{
    spend_nft_state_layer, spend_singleton, InnerSpend, SpendContext, SpendError,
};
use clvm_traits::{FromClvmError, ToClvm};
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
    OwnerPuzzleSpend(InnerSpend),                   // owner puzzle spend
    DelegatedPuzzleSpend(DelegatedPuzzle, NodePtr), // delegated puzzle info + solution
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
    let inner_spend: Result<InnerSpend, SpendError> = match &datastore_info.delegated_puzzles {
        None => match inner_datastore_spend {
            DatastoreInnerSpend::OwnerPuzzleSpend(inner_spend) => Ok(inner_spend),
            DatastoreInnerSpend::DelegatedPuzzleSpend(_, inner_spend) => {
                Err(SpendError::Eval(EvalErr(
                    inner_spend,
                    String::from("data store does not have a delegation layer"),
                )))
            }
        },
        Some(delegated_puzzles) => {
            let mut leafs: Vec<[u8; 32]> = delegated_puzzles
                .iter()
                .map(|delegated_puzzle| -> [u8; 32] { delegated_puzzle.puzzle_hash.into() })
                .collect();
            let merkle_set = MerkleSet::from_leafs(&mut leafs);
            let merkle_root: [u8; 32] = merkle_set.get_root();

            let new_inner_puzzle_mod = ctx.delegation_layer_puzzle()?;
            let new_inner_puzzle_args =
                DelegationLayerArgs::new(datastore_info.owner_puzzle_hash, merkle_root.into());

            let new_inner_puzzle = CurriedProgram {
                program: new_inner_puzzle_mod,
                args: new_inner_puzzle_args,
            };

            match inner_datastore_spend {
                DatastoreInnerSpend::OwnerPuzzleSpend(owner_puzzle_spend) => {
                    let new_inner_solution = DelegationLayerSolution {
                        merkle_proof: None,
                        puzzle_reveal: owner_puzzle_spend.puzzle(),
                        puzzle_solution: owner_puzzle_spend.solution(),
                    };

                    Ok(InnerSpend::new(
                        new_inner_puzzle.to_clvm(ctx.allocator_mut())?,
                        new_inner_solution.to_clvm(ctx.allocator_mut())?,
                    ))
                }
                DatastoreInnerSpend::DelegatedPuzzleSpend(
                    delegated_puzzle,
                    delegated_puzzle_solution,
                ) => {
                    let full_puzzle = delegated_puzzle.get_full_puzzle(ctx).map_err(|_| {
                        SpendError::FromClvm(FromClvmError::Custom(
                            "could not build datastore full puzzle".to_string(),
                        ))
                    })?;

                    let merkle_proof_result = merkle_set
                        .generate_proof(&delegated_puzzle.puzzle_hash.into())
                        .map_err(|_| {
                            SpendError::FromClvm(FromClvmError::Custom(String::from(
                                "could not generate merkle proof for spent puzzle",
                            )))
                        })?;

                    let merkle_proof = if merkle_proof_result.0 {
                        merkle_proof_result.1
                    } else {
                        return Err(SpendError::FromClvm(FromClvmError::Custom(String::from(
                            "delegated puzzle not found in merkle tree",
                        ))));
                    };

                    let new_inner_solution = DelegationLayerSolution {
                        merkle_proof: Some(merkle_proof),
                        puzzle_reveal: full_puzzle,
                        puzzle_solution: delegated_puzzle_solution,
                    };

                    Ok(InnerSpend::new(
                        new_inner_puzzle.to_clvm(ctx.allocator_mut())?,
                        new_inner_solution.to_clvm(ctx.allocator_mut())?,
                    ))
                }
            }
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

pub fn get_oracle_puzzle(
    allocator: &mut Allocator,
    oracle_puzzle_hash: &Bytes32,
    oracle_fee: u64,
) -> Result<NodePtr, EvalErr> {
    // first condition: (list CREATE_COIN oracle_puzzle_hash oracle_fee)
    // second condition: (list CREATE_PUZZLE_ANNOUNCEMENT '$')

    let first_condition = {
        let create_coin = allocator.new_number(CREATE_COIN.into())?;
        let ph = allocator.new_atom(&oracle_puzzle_hash)?;
        let fee = allocator.new_number(oracle_fee.into())?;
        let nil = allocator.nil();
        let fee_nil = allocator.new_pair(fee, nil)?;
        let ph_fee_nil = allocator.new_pair(ph, fee_nil)?;

        allocator.new_pair(create_coin, ph_fee_nil)?
    };

    let second_condition = {
        let create_puzzle_ann = allocator.new_number(CREATE_PUZZLE_ANNOUNCEMENT.into())?;
        let ann = allocator.new_atom(&['$' as u8])?;
        let nil = allocator.nil();
        let ann_nil = allocator.new_pair(ann, nil)?;

        allocator.new_pair(create_puzzle_ann, ann_nil)?
    };

    let program = {
        let one = allocator.one();
        let first_second = allocator.new_pair(first_condition, second_condition)?;
        let nil = allocator.nil();

        let conditions = allocator.new_pair(first_second, nil)?;
        allocator.new_pair(one, conditions)?
    };

    Ok(program)
}
