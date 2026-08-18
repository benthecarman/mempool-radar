use twapi_v2::api::{execute_twitter, post_2_tweets};
use twapi_v2::oauth10a::OAuthAuthentication;

#[tokio::test]
#[ignore = "posts to X using live credentials"]
async fn post_twitter_test_message() {
    let auth = OAuthAuthentication::new(
        std::env::var("MEMPOOL_RADAR_TWITTER_CONSUMER_KEY")
            .expect("MEMPOOL_RADAR_TWITTER_CONSUMER_KEY must be set"),
        std::env::var("MEMPOOL_RADAR_TWITTER_CONSUMER_SECRET")
            .expect("MEMPOOL_RADAR_TWITTER_CONSUMER_SECRET must be set"),
        std::env::var("MEMPOOL_RADAR_TWITTER_ACCESS_TOKEN")
            .expect("MEMPOOL_RADAR_TWITTER_ACCESS_TOKEN must be set"),
        std::env::var("MEMPOOL_RADAR_TWITTER_ACCESS_TOKEN_SECRET")
            .expect("MEMPOOL_RADAR_TWITTER_ACCESS_TOKEN_SECRET must be set"),
    );

    let body = post_2_tweets::Body {
        text: Some(format!(
            "mempool-radar Twitter integration test {}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock should be after UNIX epoch")
                .as_secs()
        )),
        ..Default::default()
    };

    match execute_twitter::<serde_json::Value>(post_2_tweets::Api::new(body).build(&auth)).await {
        Ok((response, headers)) => {
            println!("Twitter post succeeded: {response}");
            println!("Twitter response headers: {headers}");
        }
        Err(error) => {
            panic!("Twitter post failed: {error:#?}");
        }
    }
}
