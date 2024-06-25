use crate::{
    merkle_root_for_delegated_puzzles, merkle_tree_for_delegated_puzzles,
    puzzles_info::{DataStoreInfo, DelegatedPuzzle},
    DelegatedPuzzleInfo, DelegationLayerArgs, DelegationLayerSolution, HintContents, HintKeys,
    HintType, KeyValueList, KeyValueListItem, Metadata, ADMIN_FILTER_PUZZLE,
    ADMIN_FILTER_PUZZLE_HASH, DELEGATION_LAYER_PUZZLE, DELEGATION_LAYER_PUZZLE_HASH,
    DL_METADATA_UPDATER_PUZZLE_HASH, WRITER_FILTER_PUZZLE, WRITER_FILTER_PUZZLE_HASH,
};
use chia::traits::Streamable;
use chia_protocol::{Bytes32, CoinSpend, Program};
use chia_puzzles::{
    nft::{NftStateLayerArgs, NftStateLayerSolution, NFT_STATE_LAYER_PUZZLE_HASH},
    EveProof, Proof,
};
use chia_sdk_driver::{
    spend_singleton, InnerSpend, SpendConditions, SpendContext, SpendError, SpendableLauncher,
};
use clvm_traits::{FromClvm, FromClvmError, FromNodePtr, ToClvm};
use clvm_utils::{CurriedProgram, ToTreeHash, TreeHash};
use clvmr::{reduction::EvalErr, NodePtr};

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
    OwnerPuzzleSpend(InnerSpend), // owner puzzle spend
    DelegatedPuzzleSpend(DelegatedPuzzle, Option<NodePtr>, NodePtr), // delegated puzzle info + inner puzzle reveal + solution
}

pub fn spend_delegation_layer(
    ctx: &mut SpendContext<'_>,
    datastore_info: &DataStoreInfo,
    inner_datastore_spend: DatastoreInnerSpend,
) -> Result<InnerSpend, SpendError> {
    if datastore_info.delegated_puzzles.is_none() {
        return match inner_datastore_spend {
            DatastoreInnerSpend::OwnerPuzzleSpend(inner_spend) => Ok(inner_spend),
            DatastoreInnerSpend::DelegatedPuzzleSpend(_, __, inner_spend) => {
                Err(SpendError::Eval(EvalErr(
                    inner_spend,
                    String::from("data store does not have a delegation layer"),
                )))
            }
        };
    }

    let merkle_root =
        merkle_root_for_delegated_puzzles(&datastore_info.delegated_puzzles.as_ref().unwrap());

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

            return Ok(InnerSpend::new(
                new_inner_puzzle.to_clvm(ctx.allocator_mut())?,
                new_inner_solution.to_clvm(ctx.allocator_mut())?,
            ));
        }
        DatastoreInnerSpend::DelegatedPuzzleSpend(
            delegated_puzzle,
            delegated_inner_puzzle_reveal,
            delegated_puzzle_solution,
        ) => {
            let full_puzzle = delegated_puzzle
                .get_full_puzzle(ctx.allocator_mut(), delegated_inner_puzzle_reveal)
                .map_err(|_| {
                    SpendError::FromClvm(FromClvmError::Custom(
                        "could not build datastore full puzzle".to_string(),
                    ))
                })?;

            let merkle_proof: (u32, Vec<chia_protocol::BytesImpl<32>>) =
                merkle_tree_for_delegated_puzzles(
                    &datastore_info.delegated_puzzles.as_ref().unwrap(),
                )
                .generate_proof(delegated_puzzle.puzzle_hash)
                .ok_or(SpendError::FromClvm(FromClvmError::Custom(String::from(
                    "could not generate merkle proof for spent puzzle",
                ))))?;

            println!("merkle_proof: {:?}", merkle_proof); // todo: debug

            let solution: Vec<NodePtr> = vec![delegated_puzzle_solution];
            let new_inner_solution = DelegationLayerSolution::<NodePtr, NodePtr> {
                merkle_proof: Some(merkle_proof),
                puzzle_reveal: full_puzzle,
                puzzle_solution: ctx.alloc(&solution)?,
            };

            // todo: debug
            println!(
                "writer + filter puzzle hash: {:}",
                encode(ctx.tree_hash(full_puzzle))
            );
            // println!(
            //     "writer puzzle reveal: {:}",
            //     encode(
            //         Program::from_node_ptr(ctx.allocator_mut(), full_puzzle)
            //             .unwrap()
            //             .clone()
            //             .to_bytes()
            //             .unwrap()
            //     )
            // ); // todo: debug
            // println!(
            //     "writer puzzle solution: {:}",
            //     encode(
            //         Program::from_node_ptr(ctx.allocator_mut(), delegated_puzzle_solution)
            //             .unwrap()
            //             .clone()
            //             .to_bytes()
            //             .unwrap()
            //     )
            // ); // todo: debug
            // todo: debug

            Ok(InnerSpend::new(
                new_inner_puzzle.to_clvm(ctx.allocator_mut())?,
                new_inner_solution.to_clvm(ctx.allocator_mut())?,
            ))
        }
    }
}

pub fn spend_nft_state_layer_custom_metadata_updated<M>(
    ctx: &mut SpendContext<'_>,
    metadata: M,
    inner_spend: InnerSpend,
) -> Result<InnerSpend, SpendError>
where
    M: ToClvm<NodePtr>,
{
    let nft_state_layer = ctx.nft_state_layer()?;

    let puzzle = ctx.alloc(&CurriedProgram {
        program: nft_state_layer,
        args: NftStateLayerArgs {
            mod_hash: NFT_STATE_LAYER_PUZZLE_HASH.into(),
            metadata: metadata,
            metadata_updater_puzzle_hash: DL_METADATA_UPDATER_PUZZLE_HASH.into(),
            inner_puzzle: inner_spend.puzzle(),
        },
    })?;

    let solution = ctx.alloc(&NftStateLayerSolution {
        inner_solution: inner_spend.solution(),
    })?;

    Ok(InnerSpend::new(puzzle, solution))
}

use hex::encode;

pub fn datastore_spend(
    ctx: &mut SpendContext<'_>,
    datastore_info: &DataStoreInfo,
    inner_datastore_spend: DatastoreInnerSpend,
) -> Result<CoinSpend, SpendError> {
    // 1. Handle delegation layer spend
    let inner_spend = spend_delegation_layer(ctx, datastore_info, inner_datastore_spend)?;
    println!("inner_spend!"); // todo: debug
    println!(
        "puzzle: {:}",
        encode(
            Program::from_node_ptr(ctx.allocator_mut(), inner_spend.puzzle())
                .unwrap()
                .clone()
                .to_bytes()
                .unwrap()
        )
    ); // todo: debug
    println!(
        "solution: {:}",
        encode(
            Program::from_node_ptr(ctx.allocator_mut(), inner_spend.solution())
                .unwrap()
                .clone()
                .to_bytes()
                .unwrap()
        )
    ); // todo: debug

    // 2. Handle state layer spend
    // allows custom metadata updater hash
    let state_layer_spend =
        spend_nft_state_layer_custom_metadata_updated(ctx, &datastore_info.metadata, inner_spend)?;

    // 3. Spend singleton
    spend_singleton(
        ctx,
        datastore_info.coin,
        datastore_info.launcher_id,
        datastore_info.proof,
        state_layer_spend,
    )
}

pub struct DataStoreMintInfo {
    // NFT state layer
    pub metadata: Metadata,
    // inner puzzle (either p2 or delegation_layer + p2)
    pub owner_puzzle_hash: TreeHash,
    pub delegated_puzzles: Option<Vec<DelegatedPuzzle>>,
}

pub trait LauncherExt {
    fn mint_datastore(
        self,
        ctx: &mut SpendContext<'_>,
        info: DataStoreMintInfo,
    ) -> Result<(SpendConditions, DataStoreInfo), SpendError>
    where
        Self: Sized;
}

fn get_memos(
    ctx: &mut SpendContext<'_>,
    owner_puzzle_hash: TreeHash,
    delegated_puzzles: Option<Vec<DelegatedPuzzle>>,
) -> Result<Vec<NodePtr>, SpendError> {
    let mut memos = vec![ctx.alloc::<Bytes32>(&owner_puzzle_hash.into()).unwrap()];

    if let Some(delegated_puzzles) = delegated_puzzles {
        let hint_contents: Vec<HintContents> = delegated_puzzles
            .clone()
            .iter()
            .map(
                |delegated_puzzle: &DelegatedPuzzle| -> Result<HintContents<NodePtr>, SpendError> {
                    match delegated_puzzle.puzzle_info {
                        DelegatedPuzzleInfo::Admin(inner_puzzle_hash) => {
                            Ok(HintContents::<NodePtr> {
                                puzzle_type: HintType::AdminPuzzle,
                                puzzle_info: vec![ctx.alloc(&inner_puzzle_hash)?],
                            })
                        }
                        DelegatedPuzzleInfo::Writer(inner_puzzle_hash) => {
                            Ok(HintContents::<NodePtr> {
                                puzzle_type: HintType::WriterPuzzle,
                                puzzle_info: vec![ctx.alloc(&inner_puzzle_hash)?],
                            })
                        }
                        DelegatedPuzzleInfo::Oracle(oracle_puzzle_hash, oracle_fee) => {
                            Ok(HintContents::<NodePtr> {
                                puzzle_type: HintType::OraclePuzzle,
                                puzzle_info: vec![
                                    ctx.alloc(&oracle_puzzle_hash)?,
                                    ctx.alloc(&oracle_fee)?,
                                ],
                            })
                        }
                    }
                },
            )
            .collect::<Result<_, _>>()?;

        let results: Result<Vec<NodePtr>, SpendError> = hint_contents
            .iter()
            .map(|hint_content| {
                hint_content
                    .to_clvm(ctx.allocator_mut())
                    .map_err(SpendError::ToClvm)
            })
            .collect();

        match results {
            Ok(memos_vec) => memos.extend(memos_vec),
            Err(e) => return Err(e),
        }
    }

    println!("memos: {:?}", memos);
    Ok(memos)
}

impl<'a> LauncherExt for SpendableLauncher {
    fn mint_datastore(
        self,
        ctx: &mut SpendContext<'_>,
        info: DataStoreMintInfo,
    ) -> Result<(SpendConditions, DataStoreInfo), SpendError>
    where
        Self: Sized,
        TreeHash: ToTreeHash + ToClvm<TreeHash>,
        NodePtr: ToClvm<NodePtr>,
        Metadata<NodePtr>: ToClvm<NodePtr>,
        NftStateLayerArgs<TreeHash, TreeHash>: ToClvm<TreeHash> + ToTreeHash,
    {
        let inner_puzzle_hash: TreeHash = match &info.delegated_puzzles {
            None => info.owner_puzzle_hash,
            Some(delegated_puzzles) => DelegationLayerArgs::curry_tree_hash(
                info.owner_puzzle_hash.into(),
                merkle_root_for_delegated_puzzles(delegated_puzzles),
            ),
        };

        let metadata_ptr = ctx.alloc(&info.metadata)?;
        let metadata_hash = ctx.tree_hash(metadata_ptr);
        let state_layer_hash = CurriedProgram {
            program: NFT_STATE_LAYER_PUZZLE_HASH,
            args: NftStateLayerArgs::<TreeHash, TreeHash> {
                mod_hash: NFT_STATE_LAYER_PUZZLE_HASH.into(),
                metadata: metadata_hash,
                metadata_updater_puzzle_hash: DL_METADATA_UPDATER_PUZZLE_HASH.into(),
                inner_puzzle: inner_puzzle_hash,
            },
        }
        .tree_hash();

        let metadata_list = Metadata::<NodePtr>::from_clvm(ctx.allocator_mut(), metadata_ptr)?;
        let metadata_list_ptr = ctx.alloc(&metadata_list)?;
        let kv_list: KeyValueList<NodePtr> = vec![
            KeyValueListItem::<NodePtr> {
                key: HintKeys::MetadataReveal.value(),
                value: vec![metadata_list_ptr],
            },
            KeyValueListItem {
                key: HintKeys::DelegationLayerInfo.value(),
                value: get_memos(ctx, info.owner_puzzle_hash, info.delegated_puzzles.clone())?,
            },
        ];

        let launcher_coin = self.coin();
        let (chained_spend, eve_coin) = self.spend(ctx, state_layer_hash.into(), kv_list)?;

        let proof: Proof = Proof::Eve(EveProof {
            parent_coin_info: launcher_coin.parent_coin_info,
            amount: launcher_coin.amount,
        });

        let data_store_info: DataStoreInfo = DataStoreInfo {
            launcher_id: launcher_coin.coin_id(),
            coin: eve_coin,
            proof,
            metadata: info.metadata.clone(),
            owner_puzzle_hash: info.owner_puzzle_hash.into(),
            delegated_puzzles: info.delegated_puzzles.clone(),
        };

        Ok((chained_spend, data_store_info))
    }
}

#[cfg(test)]
mod tests {
    use crate::print_spend_bundle_to_file;

    use super::*;

    use chia::bls::G2Element;
    use chia_protocol::Bytes32;
    use chia_puzzles::standard::StandardArgs;
    use chia_sdk_driver::{Launcher, P2Spend, StandardSpend};
    use chia_sdk_test::{test_transaction, Simulator};
    use clvmr::Allocator;

    fn assert_datastores_eq(
        ctx: &mut SpendContext<'_>,
        datastore_info: &DataStoreInfo,
        new_datastore_info: &DataStoreInfo,
    ) {
        assert_eq!(
            new_datastore_info.coin.coin_id(),
            datastore_info.coin.coin_id()
        );
        assert_eq!(new_datastore_info.launcher_id, datastore_info.launcher_id);
        assert_eq!(new_datastore_info.proof, datastore_info.proof);

        let ptr1 = ctx.alloc(&new_datastore_info.metadata).unwrap();
        let ptr2 = ctx.alloc(&datastore_info.metadata).unwrap();
        assert_eq!(ctx.tree_hash(ptr1), ctx.tree_hash(ptr2));

        assert_eq!(
            new_datastore_info.owner_puzzle_hash,
            datastore_info.owner_puzzle_hash
        );

        match datastore_info.delegated_puzzles.clone() {
            Some(delegated_puzzles) => {
                // when comparing delegated puzzles, don't care about
                // their full_puzzle attribute
                let new_delegated_puzzles = new_datastore_info.delegated_puzzles.clone().unwrap();
                for i in 0..delegated_puzzles.len() {
                    let a = delegated_puzzles.get(i).unwrap();
                    let b = new_delegated_puzzles.get(i).unwrap();

                    assert_eq!(a.puzzle_hash, b.puzzle_hash);
                    assert_eq!(a.puzzle_info, b.puzzle_info);
                }
            }
            None => {
                assert!(new_datastore_info.delegated_puzzles.is_none());
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, ToClvm, FromClvm)]
    #[clvm(list)]
    pub struct NewMetadataCondition<S = NodePtr> {
        pub condition: i32,
        pub metadata_updater_reveal: i32, // 11 - ssh
        pub metadata_updater_solution: S,
    }

    #[derive(Debug, Clone, PartialEq, Eq, ToClvm, FromClvm)]
    #[clvm(list)]
    pub struct DLMetadataSolutionMetadataPart<T = NodePtr> {
        pub new_metadata: T,
        pub new_metadata_updater_ph: u8, // 0
    }

    #[derive(Debug, Clone, PartialEq, Eq, ToClvm, FromClvm)]
    #[clvm(list)]
    pub struct DLMetadataSolution<T = NodePtr> {
        pub metadata_part: DLMetadataSolutionMetadataPart<T>,
        pub metadata_updater_solution: u8, // 0
    }

    #[tokio::test]
    async fn test_simple_datastore() -> anyhow::Result<()> {
        let sim = Simulator::new().await?;
        let peer = sim.connect().await?;

        let sk = sim.secret_key().await?;
        let pk = sk.public_key();

        let puzzle_hash = StandardArgs::curry_tree_hash(pk).into();
        let coin = sim.mint_coin(puzzle_hash, 1).await;

        let mut allocator = Allocator::new();
        let ctx = &mut SpendContext::new(&mut allocator);

        let (launch_singleton, datastore_info) = Launcher::new(coin.coin_id(), 1)
            .create(ctx)?
            .mint_datastore(
                ctx,
                DataStoreMintInfo {
                    metadata: Metadata { items: Vec::new() },
                    owner_puzzle_hash: puzzle_hash.into(),
                    delegated_puzzles: None,
                },
            )?;

        StandardSpend::new()
            .chain(launch_singleton)
            .finish(ctx, coin, pk)?;

        let spends = ctx.take_spends();
        print_spend_bundle_to_file(spends.clone(), G2Element::default(), "sb.debug");
        for spend in spends {
            if spend.coin.coin_id() == datastore_info.launcher_id {
                let new_datastore_info = DataStoreInfo::from_spend(ctx.allocator_mut(), &spend)
                    .unwrap()
                    .unwrap();

                assert_datastores_eq(ctx, &datastore_info, &new_datastore_info);
            }

            ctx.spend(spend);
        }

        let datastore_inner_spend = StandardSpend::new()
            .chain(SpendConditions::new().create_coin(ctx, puzzle_hash, 1)?)
            .inner_spend(ctx, pk)?;
        let inner_datastore_spend = DatastoreInnerSpend::OwnerPuzzleSpend(datastore_inner_spend);
        let new_spend = datastore_spend(ctx, &datastore_info, inner_datastore_spend)?;
        ctx.spend(new_spend);

        test_transaction(
            &peer,
            ctx.take_spends(),
            &[sk],
            sim.config().genesis_challenge,
        )
        .await;

        // Make sure the datastore was created.
        let coin_state = sim
            .coin_state(datastore_info.coin.coin_id())
            .await
            .expect("expected datastore coin");
        assert_eq!(coin_state.coin, datastore_info.coin);
        assert!(coin_state.spent_height.is_some());

        Ok(())
    }

    #[tokio::test]
    async fn test_datastore_with_delegation_layer() -> anyhow::Result<()> {
        let sim = Simulator::new().await?;
        let peer = sim.connect().await?;

        let owner_sk = sim.secret_key().await?;
        let owner_pk = owner_sk.public_key();

        let admin_sk = sim.secret_key().await?;
        let admin_pk = admin_sk.public_key();

        let writer_sk = sim.secret_key().await?;
        let writer_pk = writer_sk.public_key();

        let oracle_puzzle_hash: Bytes32 = [1; 32].into();
        let oracle_fee = 1000;

        let owner_puzzle_hash = StandardArgs::curry_tree_hash(owner_pk).into();
        let coin = sim.mint_coin(owner_puzzle_hash, 1).await;

        let mut allocator = Allocator::new();
        let ctx = &mut SpendContext::new(&mut allocator);

        // let owner_puzzle: NodePtr = CurriedProgram {
        //     program: ctx.standard_puzzle()?,
        //     args: StandardArgs::new(owner_pk),
        // }
        // .to_clvm(ctx.allocator_mut())?;

        let admin_puzzle: NodePtr = CurriedProgram {
            program: ctx.standard_puzzle()?,
            args: StandardArgs::new(admin_pk),
        }
        .to_clvm(ctx.allocator_mut())?;

        let writer_puzzle: NodePtr = CurriedProgram {
            program: ctx.standard_puzzle()?,
            args: StandardArgs::new(writer_pk),
        }
        .to_clvm(ctx.allocator_mut())?;

        let admin_delegated_puzzle =
            DelegatedPuzzle::from_admin_inner_puzzle(ctx.allocator_mut(), admin_puzzle).unwrap();
        let writer_delegated_puzzle =
            DelegatedPuzzle::from_writer_inner_puzzle(ctx.allocator_mut(), writer_puzzle).unwrap();
        println!(
            "writer puzzle hash: {:}",
            encode(writer_delegated_puzzle.puzzle_hash)
        ); // todo: debug
        let (launch_singleton, datastore_info) = Launcher::new(coin.coin_id(), 1)
            .create(ctx)?
            .mint_datastore(
                ctx,
                DataStoreMintInfo {
                    metadata: Metadata { items: vec![] },
                    owner_puzzle_hash: owner_puzzle_hash.into(),
                    delegated_puzzles: Some(vec![
                        admin_delegated_puzzle,
                        writer_delegated_puzzle,
                        DelegatedPuzzle::new_oracle(oracle_puzzle_hash, oracle_fee).unwrap(),
                    ]),
                },
            )?;

        StandardSpend::new()
            .chain(launch_singleton)
            .finish(ctx, coin, owner_pk)?;

        let spends = ctx.take_spends();
        for spend in spends {
            if spend.coin.coin_id() == datastore_info.launcher_id {
                let new_datastore_info = DataStoreInfo::from_spend(ctx.allocator_mut(), &spend)
                    .unwrap()
                    .unwrap();

                assert_datastores_eq(ctx, &datastore_info, &new_datastore_info);
            }

            ctx.spend(spend);
        }

        // writer: update metadata
        let new_metadata = Metadata::<NodePtr> {
            items: vec![ctx.alloc(&Bytes32::new([0; 32]))?],
        };
        let new_metadata_condition =
            NewMetadataCondition::<DLMetadataSolution<Metadata<NodePtr>>> {
                condition: -24,
                metadata_updater_reveal: 11,
                metadata_updater_solution: DLMetadataSolution {
                    metadata_part: DLMetadataSolutionMetadataPart {
                        new_metadata: new_metadata,
                        new_metadata_updater_ph: 0,
                    },
                    metadata_updater_solution: 0,
                },
            }
            .to_clvm(ctx.allocator_mut())
            .unwrap();

        let new_metadata_inner_spend = StandardSpend::new()
            .chain(SpendConditions::new().raw_condition(new_metadata_condition))
            .inner_spend(ctx, writer_pk)?;

        // delegated puzzle info + inner puzzle reveal + solution
        let inner_datastore_spend = DatastoreInnerSpend::DelegatedPuzzleSpend(
            writer_delegated_puzzle,
            Some(writer_puzzle),
            new_metadata_inner_spend.solution(),
        );
        let new_spend = datastore_spend(ctx, &datastore_info, inner_datastore_spend)?;
        ctx.spend(new_spend.clone());

        // let new_datastore_info =
        //     DataStoreInfo::from_spend(ctx.allocator_mut(), &new_spend).unwrap();
        // assert!(new_datastore_info.is_none());

        // finally, remove delegation layer altogether
        // let datastore_remove_delegation_layer_inner_spend = StandardSpend::new()
        //     .chain(SpendConditions::new().create_coin(ctx, owner_puzzle_hash, 1)?)
        //     .inner_spend(ctx, owner_pk)?;
        // let inner_datastore_spend =
        //     DatastoreInnerSpend::OwnerPuzzleSpend(datastore_remove_delegation_layer_inner_spend);
        // let new_spend = datastore_spend(ctx, &datastore_info, inner_datastore_spend)?;
        // ctx.spend(new_spend.clone());

        // let new_datastore_info = DataStoreInfo::from_spend(ctx.allocator_mut(), &new_spend)
        //     .unwrap()
        //     .unwrap();
        // assert!(new_datastore_info.delegated_puzzles.is_none());
        // assert_eq!(new_datastore_info.owner_puzzle_hash, owner_puzzle_hash);

        let spends = ctx.take_spends();
        print_spend_bundle_to_file(spends.clone(), G2Element::default(), "sb.debug");
        test_transaction(
            &peer,
            spends,
            &[owner_sk, admin_sk, writer_sk],
            sim.config().genesis_challenge,
        )
        .await;

        // Make sure the datastore was created.
        let coin_state = sim
            .coin_state(datastore_info.coin.coin_id())
            .await
            .expect("expected datastore coin");
        assert_eq!(coin_state.coin, datastore_info.coin);
        assert!(coin_state.spent_height.is_some());

        Ok(())
    }
}
