//! Trait for visual, interactive UI elements.
use color_eyre::eyre;
use crossterm::event::{KeyEvent, MouseEvent};
use ratatui::{layout::Rect, Frame};
use tokio::sync::mpsc::UnboundedSender;

use crate::frontend::{action::Action, event::Event};

/// Implementors of this trait can be added to the main event loop. They can receive evenets,
/// update their states, and be rendered on the screen.
pub trait Component {}
