#[derive(Debug, Clone, Default)]
pub enum PointError {
    #[default]
    InvalidPoint,
    UnreachableError,
}
