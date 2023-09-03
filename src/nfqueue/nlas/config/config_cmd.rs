// SPDX-License-Identifier: MIT

use netlink_packet_utils::{buffer, DecodeError, Emitable, Parseable};

use crate::constants::{
    NFQNL_CFG_CMD_BIND, NFQNL_CFG_CMD_NONE, NFQNL_CFG_CMD_PF_BIND,
    NFQNL_CFG_CMD_PF_UNBIND, NFQNL_CFG_CMD_UNBIND,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigCmdType {
    None,
    Bind,
    Unbind,
    PfBind,
    PfUnbind,
    Other(u8),
}

impl From<ConfigCmdType> for u8 {
    fn from(cmd: ConfigCmdType) -> Self {
        match cmd {
            ConfigCmdType::None => NFQNL_CFG_CMD_NONE,
            ConfigCmdType::Bind => NFQNL_CFG_CMD_BIND,
            ConfigCmdType::Unbind => NFQNL_CFG_CMD_UNBIND,
            ConfigCmdType::PfBind => NFQNL_CFG_CMD_PF_BIND,
            ConfigCmdType::PfUnbind => NFQNL_CFG_CMD_PF_UNBIND,
            ConfigCmdType::Other(cmd) => cmd,
        }
    }
}

impl From<u8> for ConfigCmdType {
    fn from(cmd: u8) -> Self {
        match cmd {
            NFQNL_CFG_CMD_NONE => ConfigCmdType::None,
            NFQNL_CFG_CMD_BIND => ConfigCmdType::Bind,
            NFQNL_CFG_CMD_UNBIND => ConfigCmdType::Unbind,
            NFQNL_CFG_CMD_PF_BIND => ConfigCmdType::PfBind,
            NFQNL_CFG_CMD_PF_UNBIND => ConfigCmdType::PfUnbind,
            cmd => ConfigCmdType::Other(cmd),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigCmd {
    cmd: ConfigCmdType,
    pf: u16,
}

impl ConfigCmd {
    pub fn new(cmd: ConfigCmdType, pf: u16) -> Self {
        Self { cmd, pf }
    }
}

const CONFIG_CMD_BUFFER_SIZE: usize = 4;

buffer!(ConfigCmdBuffer(CONFIG_CMD_BUFFER_SIZE) {
    cmd: (u8, 0),
    pad: (u8, 1),
    pf: (u16, 2..4)
});

impl From<&ConfigCmdBuffer<&[u8]>> for ConfigCmd {
    fn from(buffer: &ConfigCmdBuffer<&[u8]>) -> Self {
        ConfigCmd::new(
            ConfigCmdType::from(buffer.cmd()),
            u16::from_be(buffer.pf()),
        )
    }
}

impl Parseable<[u8]> for ConfigCmd {
    fn parse(buffer: &[u8]) -> Result<Self, DecodeError> {
        match ConfigCmdBuffer::new_checked(buffer) {
            Ok(buffer) => Ok(ConfigCmd::from(&buffer)),
            Err(error) => Err(error),
        }
    }
}

impl Emitable for ConfigCmd {
    fn buffer_len(&self) -> usize {
        CONFIG_CMD_BUFFER_SIZE
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = ConfigCmdBuffer::new(buffer);
        buffer.set_cmd(u8::from(self.cmd));
        buffer.set_pad(0);
        buffer.set_pf(u16::to_be(self.pf));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        let buffer: [u8; CONFIG_CMD_BUFFER_SIZE] = [
            0x01, // NFQNL_CFG_CMD_BIND
            0x00, // pad
            0x00, 0x02, // AF_INET 0x0002
        ];
        match ConfigCmd::parse(&buffer) {
            Ok(command) => {
                assert_eq!(command.cmd, ConfigCmdType::Bind);
                assert_eq!(command.pf, 0x0002);
            }
            Err(_) => assert!(false),
        }
    }

    #[test]
    fn test_emit() {
        let mut buffer = vec![0; 4];
        ConfigCmd::new(ConfigCmdType::Bind, 0x0002).emit(&mut buffer);
        assert_eq!(
            buffer,
            [
                0x01, // NFQNL_CFG_CMD_BIND
                0x00, // pad
                0x00, 0x02, // AF_INET 0x0002
            ]
        )
    }
}
