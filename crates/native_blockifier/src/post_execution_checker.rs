use blockifier::execution::call_info::CallInfo;
use blockifier::transaction::objects::AccountTransactionContext;
use starknet_api::transaction::Fee;

use crate::errors::NativeBlockifierValidationError;

pub type NativeBlockifierPostCheckResult<T> = Result<T, NativeBlockifierValidationError>;

pub struct PostExecutionChecker {}

// TODO
// impl PostExecutionChecker {
// }

impl InsufficientFeeChecker for PostExecutionChecker {}

pub struct PostValidationChecker {
    pub account_tx_context: AccountTransactionContext,
    pub call_info: Option<CallInfo>,
    pub actual_fee: Fee,
}

impl PostValidationChecker {
    pub fn post_validate(self) -> NativeBlockifierPostCheckResult<Option<CallInfo>> {
        let max_fee = self.account_tx_context.max_fee();
        self.post_check(max_fee, self.actual_fee).map(|_| self.call_info)
    }
}

impl InsufficientFeeChecker for PostValidationChecker {}

// TODO: Generalize the trait name once more checks are added, if necessary.
pub trait InsufficientFeeChecker {
    fn post_check(&self, max_fee: Fee, actual_fee: Fee) -> NativeBlockifierPostCheckResult<()> {
        // FIXME BEFORE MERGE: Should i use `charge_fee` here instead? (probably don't run this
        // method at all if charge_fee is false?)
        if max_fee == Fee(0) {
            return Ok(());
        }

        if actual_fee <= max_fee {
            Ok(())
        } else {
            Err(NativeBlockifierValidationError::InsufficientMaxFee { max_fee, actual_fee })?
        }
    }
}
