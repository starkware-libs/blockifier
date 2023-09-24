use std::str::FromStr;

use proc_macro::TokenStream;
use proc_macro2::{Ident, Span, TokenStream as TokenStream2};
use quote::{quote, quote_spanned};
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::token::Comma;
use syn::{
    parse_macro_input, FnArg, Item, ItemFn, Pat, PatIdent, PatType, Path, Signature, Type, TypePath,
};

/// To add a new transaction version to tests, add it to the relevant array below.
pub const INVOKE_VERSIONS: [u8; 3] = [0, 1, 3];
pub const DECLARE_VERSIONS: [u8; 4] = [0, 1, 2, 3];
pub const DEPLOY_ACCOUNT_VERSIONS: [u8; 3] = [0, 1, 3];

#[derive(Debug, thiserror::Error)]
enum VaryVersionError {
    #[error("The function must take a TransactionVersion argument with the correct name.")]
    MissingArg,
    #[error("Multiple arguments of the same name ({0:?}).")]
    MultipleArgs(String),
    #[error("Argument '({0:?})' must be of type '({1:?})'.")]
    IncorrectArgType(String, String),
}

/// Outputs a compile error with the given message, at the given span.
fn spanned_compile_error(span: Span, message: &str) -> TokenStream {
    // Wrap the error message string in quotes, so that it is a valid Rust string literal.
    match TokenStream2::from_str(&format!("\"{}\"", message)) {
        Ok(message_token) => quote_spanned! { span => compile_error!(#message_token); }.into(),
        Err(error) => {
            // Error message cannot be tokenized for some reason.
            // Fail compilation with a message that is guaranteed to be tokenizable.
            let new_message = format!("Error while generating error message: {:?}", error);
            let new_message_token =
                TokenStream2::from_str(&format!("\"{}\"", new_message)).unwrap();
            quote_spanned! { error.span() => compile_error!(#new_message_token); }.into()
        }
    }
}

/// Checks if the given attribute argument matches the transaction version argument in the function
/// signature.
fn matches_transaction_version_arg(
    version_var_item: &Ident,
    arg: &FnArg,
) -> Result<bool, VaryVersionError> {
    if let FnArg::Typed(PatType { pat, ty, .. }) = arg {
        if let Pat::Ident(PatIdent { ident, .. }) = pat.as_ref() {
            if ident == version_var_item {
                // Function argument name matches attribute argument; check function argument type.
                if let Type::Path(TypePath { path: Path { segments, .. }, .. }) = ty.as_ref() {
                    if segments.len() == 1 && segments[0].ident == "TransactionVersion" {
                        return Ok(true);
                    } else {
                        return Err(VaryVersionError::IncorrectArgType(
                            ident.to_string(),
                            segments[0].ident.to_string(),
                        ));
                    }
                }
            }
        }
    };
    Ok(false)
}

/// Removes the invoke version argument from the function signature.
/// If the argument is not found, or appears mor ethan once, an error is returned.
fn extract_transaction_version_arg(
    sig: Signature,
    version_var_item: &Ident,
) -> Result<Signature, VaryVersionError> {
    let mut new_inputs: Punctuated<FnArg, Comma> = Punctuated::new();
    for input in sig.inputs.clone().into_iter() {
        if !matches_transaction_version_arg(version_var_item, &input)? {
            new_inputs.push(input);
        }
    }

    // Check for correct number of arguments.
    if new_inputs.len() == sig.inputs.len() {
        return Err(VaryVersionError::MissingArg);
    }
    if new_inputs.len() < sig.inputs.len() - 1 {
        return Err(VaryVersionError::MultipleArgs(version_var_item.to_string()));
    }

    Ok(Signature { inputs: new_inputs, ..sig })
}

/// Repeats the input stream, once per version.
/// Each repetition assigns the version to the variable named by the argument to the macro.
///
/// Example input:
/// #[vary_over_invoke_versions(invoke_version)]
/// #[rstest]
/// fn test_example(invoke_version: TransactionVersion) {
///     println!("Invoke transaction version: {:?}", invoke_version);
/// }
///
/// Example output:
/// #[rstest]
/// fn test_example_invoke_version_v0() {
///     let invoke_version = TransactionVersion::from(StarkFelt::from(0));
///     println!("Invoke transaction version: {:?}", invoke_version);
/// }
/// #[rstest]
/// fn test_example_invoke_version_v1() {
///     let invoke_version = TransactionVersion::from(StarkFelt::from(1));
///     println!("Invoke transaction version: {:?}", invoke_version);
/// }
/// #[rstest]
/// fn test_example_invoke_version_v3() {
///     let invoke_version = TransactionVersion::from(StarkFelt::from(3));
///     println!("Invoke transaction version: {:?}", invoke_version);
/// }
pub fn vary_over_versions(args: TokenStream, stream: TokenStream, versions: &[u8]) -> TokenStream {
    // Argument to macro should match the name of the variable that will contain the transaction
    // version.
    let version_var_item = parse_macro_input!(args as Ident);

    match parse_macro_input!(stream as Item) {
        Item::Fn(ItemFn { attrs, vis, sig, block }) => {
            // Find and extract the invoke version argument from the function signature.
            match extract_transaction_version_arg(sig, &version_var_item) {
                Ok(new_sig) => TokenStream2::from_iter(versions.iter().map(|i| {
                    let renamed_sig = Signature {
                        ident: syn::Ident::new(
                            &format!("{}_v{}", new_sig.ident, i),
                            new_sig.ident.span(),
                        ),
                        ..new_sig.clone()
                    };
                    quote! {
                        #(#attrs)*
                        #vis #renamed_sig {
                            let #version_var_item = TransactionVersion(StarkFelt::from(#i));
                            #block
                        }
                    }
                }))
                .into(),
                Err(VaryVersionError::MissingArg) => quote_spanned! {
                    version_var_item.span() =>
                        compile_error!("Missing transaction version argument.");
                }
                .into(),
                Err(VaryVersionError::MultipleArgs(arg)) => spanned_compile_error(
                    version_var_item.span(),
                    &format!("Multiple identical transaction version arguments: {}", arg),
                ),
                Err(VaryVersionError::IncorrectArgType(arg, wrong_type)) => spanned_compile_error(
                    version_var_item.span(),
                    &format!(
                        "Argument type of version argument {} must be TransactionVersion, got {}.",
                        arg, wrong_type
                    ),
                ),
            }
        }
        item => {
            spanned_compile_error(item.span(), "The attribute is only applicable to functions.")
        }
    }
}
