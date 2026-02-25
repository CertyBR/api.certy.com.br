pub mod certificates;
pub mod health;

use std::sync::Arc;

use axum::Router;

use crate::state::AppState;

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .merge(health::router())
        .nest("/api/v1/certificates", certificates::router())
        .with_state(state)
}
