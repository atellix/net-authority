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

pub const MAX_RBAC: u32 = 512;

#[repr(u16)]
#[derive(PartialEq, Debug, Eq, Copy, Clone)]
pub enum DT { // Data types
    UserRBACMap,                 // CritMap 
    UserRBAC,                    // Slabvec
}

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

#[derive(Copy, Clone)]
#[repr(packed)]
pub struct UserRBAC {
    pub status: Status,
    pub user_key: Pubkey,
    pub role: Role,
}
unsafe impl Zeroable for UserRBAC {}
unsafe impl Pod for UserRBAC {}

impl UserRBAC {
    pub fn status(&self) -> Status {
        self.status
    }

    pub fn set_status(&mut self, new_status: Status) {
        self.status = new_status
    }

    pub fn user_key(&self) -> Pubkey {
        self.user_key
    }

    pub fn role(&self) -> Role {
        self.role
    }
}

fn verify_program_owner(program_id: &Pubkey, acc_prog: &AccountInfo, acc_pdat: &AccountInfo, acc_user: &AccountInfo) -> ProgramResult {
    if *acc_prog.key != *program_id {
        msg!("Program account is not this program");
        return Err(ErrorCode::AccessDenied.into());
    }
    //msg!("Verified program account");
    let data: &[u8] = &acc_prog.try_borrow_data()?;
    let res = parse_bpf_upgradeable_loader(data);
    if ! res.is_ok() {
        msg!("Failed to decode program");
        return Err(ErrorCode::AccessDenied.into());
    }
    let program_data = match res.unwrap() {
        BpfUpgradeableLoaderAccountType::Program(info) => info.program_data,
        _ => {
            msg!("Invalid program account type");
            return Err(ErrorCode::AccessDenied.into());
        },
    };
    if acc_pdat.key.to_string() != program_data {
        msg!("Program data address does not match");
        return Err(ErrorCode::AccessDenied.into());
    }
    //msg!("Verified program data account");
    let data2: &[u8] = &acc_pdat.try_borrow_data()?;
    let res2 = parse_bpf_upgradeable_loader(data2);
    if ! res2.is_ok() {
        msg!("Failed to decode program data");
        return Err(ErrorCode::AccessDenied.into());
    }
    let program_owner = match res2.unwrap() {
        BpfUpgradeableLoaderAccountType::ProgramData(info) => info.authority.unwrap(),
        _ => {
            msg!("Invalid program data account type");
            return Err(ErrorCode::AccessDenied.into());
        },
    };
    if acc_user.key.to_string() != program_owner {
        msg!("Root admin is not program owner");
        return Err(ErrorCode::AccessDenied.into());
    }
    //msg!("Verified program owner");
    Ok(())
}

fn verify_matching_accounts(left: &Pubkey, right: &Pubkey, error_msg: Option<String>) -> ProgramResult {
    if *left != *right {
        if error_msg.is_some() {
            msg!(error_msg.unwrap().as_str());
            msg!("Expected: {}", left.to_string());
            msg!("Received: {}", right.to_string());
        }
        return Err(ErrorCode::InvalidAccount.into());
    }
    Ok(())
}

#[program]
mod net_authority {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>,
        inp_root_nonce: u8
    ) -> ProgramResult {
        let acc_prog = &ctx.accounts.program.to_account_info();
        let acc_pdat = &ctx.accounts.program_data.to_account_info();
        let acc_user = &ctx.accounts.program_admin.to_account_info();
        verify_program_owner(ctx.program_id, &acc_prog, &acc_pdat, &acc_user)?;
        let av = ctx.remaining_accounts;
        let funder_info = av.get(0).unwrap();
        let data_account_info = av.get(1).unwrap();
        let system_program_info = av.get(2).unwrap();
        let (data_account_address, bump_seed) = Pubkey::find_program_address(
            &[ctx.program_id.as_ref()],
            ctx.program_id,
        );
        if data_account_address != *data_account_info.key {
            msg!("Invalid root data account");
            return Err(ProgramError::InvalidDerivedAccount);
        }
        let account_signer_seeds: &[&[_]] = &[
            ctx.program_id.as_ref(),
            &[inp_root_nonce],
        ];
        msg!("Create root data account");
        invoke_signed(
            &system_instruction::create_account(
                funder_info.key,
                data_account_info.key,
                root_rent,
                root_size,
                ctx.program_id
            ),
            &[
                funder_info.clone(),
                data_account_info.clone(),
                system_program_info.clone(),
            ],
            &[account_signer_seeds],
        )?;
        let acc_root = &ctx.accounts.root_data.to_account_info();
        let acc_auth = &ctx.accounts.auth_data.to_account_info();
        let ra = RootData {
            root_authority: *acc_auth.key,
        };
        let mut root_data = acc_root.try_borrow_mut_data()?;
        let mut root_dst: &mut [u8] = &mut root_data;
        let mut root_crs = std::io::Cursor::new(root_dst);
        ra.try_serialize(&mut root_crs)?;

        let auth_data: &mut[u8] = &mut acc_auth.try_borrow_mut_data()?;
        let rd = SlabPageAlloc::new(auth_data);
        rd.setup_page_table();
        rd.allocate::<CritMapHeader, AnyNode>(DT::UserRBACMap as u16, MAX_RBAC as usize).expect("Failed to allocate");
        rd.allocate::<SlabVec, UserRBAC>(DT::UserRBAC as u16, MAX_RBAC as usize).expect("Failed to allocate");
        Ok(())
    }

    pub fn grant(ctx: Context<Grant>) -> ProgramResult {
        Ok(())
    }

    pub fn revoke(ctx: Context<Revoke>) -> ProgramResult {
        Ok(())
    }

    pub fn approve_merchant(ctx: Context<ApproveMerchant>) -> ProgramResult {
        Ok(())
    }

    pub fn update_merchant(ctx: Context<UpdateMerchant>) -> ProgramResult {
        Ok(())
    }

    pub fn approve_manager(ctx: Context<ApproveManager>) -> ProgramResult {
        Ok(())
    }

    pub fn update_manager(ctx: Context<UpdateManager>) -> ProgramResult {
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
}

#[derive(Accounts)]
pub struct Grant<'info> {
}

#[derive(Accounts)]
pub struct Revoke<'info> {
}

#[derive(Accounts)]
pub struct ApproveMerchant<'info> {
}

#[derive(Accounts)]
pub struct UpdateMerchant<'info> {
}

#[derive(Accounts)]
pub struct ApproveManager<'info> {
}

#[derive(Accounts)]
pub struct UpdateManager<'info> {
}

#[account]
pub struct RootData {
    pub root_authority: Pubkey,
}

impl RootData {
    pub fn root_authority(&self) -> Pubkey {
        self.root_authority
    }

    pub fn set_root_authority(&mut self, new_authority: Pubkey) {
        self.root_authority = new_authority
    }
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

#[error]
pub enum ErrorCode {
    #[msg("Invalid derived account")]
    InvalidDerivedAccount,
}
