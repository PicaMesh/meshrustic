// The identity migration can be tested on the host because these cases never read MMIO.
#[allow(dead_code)]
#[path = "../../nrf52840/src/node.rs"]
mod node;
