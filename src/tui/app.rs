//! Responsible for application state and component management.
use color_eyre::eyre;
use crossterm::event::KeyEvent;

use super::{
    components::{Component, Login, Logo},
    mode::Mode,
    ti::Ti,
};
use crate::config::Config;

/// Application.
pub struct App {
    pub config: Config,
    pub components: Vec<Box<dyn Component>>,
    pub should_quit: bool,
    pub mode: Mode,
    pub last_tick_key_events: Vec<KeyEvent>,
}
impl App {
    /// Create a new App. Create all [Component]s. Add all [Component]s to the App.
    pub fn new() -> eyre::Result<Self> {
        // Create all components.
        let login = Login::default();
        let logo = Logo::default();

        let config = Config::new()?;
        let components: Vec<Box<dyn Component>> = vec![Box::new(login), Box::new(logo)];
        let should_quit = false;
        let mode = Mode::default();
        let last_tick_key_events = vec![];

        Ok(Self {
            config,
            components,
            should_quit,
            mode,
            last_tick_key_events,
        })
    }

    /// Link action senders & receivers to [Component]s. After that, start the [TI]
    pub async fn run(&mut self) -> eyre::Result<()> {
        let mut ti = Ti::new()?;
        // Connect action senders/receivers.
        // Start the TI.
        // Connect the components.
        // Initialise the components.
        // LOOP: Receive events from the TI.
        // Exit the TI.
        Ok(())
    }
}
