use uuid::Uuid;
use std::{ mem::size_of, io::Cursor };
use bytemuck::{ Pod, Zeroable };
use byte_slice_cast::*;
use num_enum::TryFromPrimitive;
use anchor_lang::prelude::*;
use anchor_spl::token::{ self, Transfer, TokenAccount, Mint, Approve };
use solana_program::{
    program::{ invoke_signed },
    account_info::AccountInfo,
    system_instruction,
};

#[repr(u32)]
#[derive(PartialEq, Debug, Eq, Copy, Clone, TryFromPrimitive)]
pub enum Approval {
    Manager,
    Merchant,
}

#[repr(u32)]
#[derive(PartialEq, Debug, Eq, Copy, Clone, TryFromPrimitive)]
pub enum Role {             // Role-based access control:
    ManagerAdmin,           // Can create/modify manager approvals (processes subscriptions)
    MerchantAdmin,          // Can create/modify merchant approvals (receives subscription payments)
}

#[program]
mod net_authority {
    use super::*;

    //pub fn activate(ctx: Context<Activate>) -> ProgramResult {}
    //pub fn grant(ctx: Context<Grant>) -> ProgramResult {}
    //pub fn revoke(ctx: Context<Revoke>) -> ProgramResult {}
    //pub fn approve_merchant(ctx: Context<ApproveMerchant>) -> ProgramResult {}
    //pub fn update_merchant(ctx: Context<UpdateMerchant>) -> ProgramResult {}
    //pub fn approve_manager(ctx: Context<ApproveManager>) -> ProgramResult {}
    //pub fn update_manager(ctx: Context<UpdateManager>) -> ProgramResult {}
}

#[account]
pub struct MerchantApproval {
    pub active: bool,
    pub merchant_key: Pubkey,
    pub token_mint: Pubkey,
    pub fees_account: Pubkey,
    pub fees_bps: u32,
}

#[account]
pub struct ManagerApproval {
    pub active: bool,
    pub manager_key: Pubkey,
}

