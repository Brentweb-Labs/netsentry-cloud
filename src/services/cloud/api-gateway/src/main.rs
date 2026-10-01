#[tokio::main]
async fn main() -> anyhow::Result<()> {
    netsentry_gateway::run().await
}
