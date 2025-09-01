pub enum Chain {
    Sui,
    Aptos,
}

impl Chain {
    pub fn supported_chains() -> Vec<Chain> {
        vec![Chain::Sui, Chain::Aptos]
    }
}