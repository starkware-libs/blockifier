use proc_macro::TokenStream;

mod vary_versions;

use vary_versions::{
    vary_over_versions, DECLARE_VERSIONS, DEPLOY_ACCOUNT_VERSIONS, INVOKE_VERSIONS,
};

#[proc_macro_attribute]
pub fn vary_over_invoke_versions(args: TokenStream, stream: TokenStream) -> TokenStream {
    vary_over_versions(args, stream, &INVOKE_VERSIONS)
}

#[proc_macro_attribute]
pub fn vary_over_declare_versions(args: TokenStream, stream: TokenStream) -> TokenStream {
    vary_over_versions(args, stream, &DECLARE_VERSIONS)
}

#[proc_macro_attribute]
pub fn vary_over_deploy_account_versions(args: TokenStream, stream: TokenStream) -> TokenStream {
    vary_over_versions(args, stream, &DEPLOY_ACCOUNT_VERSIONS)
}
