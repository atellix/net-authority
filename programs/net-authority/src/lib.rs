//use uuid::Uuid;
use std::{ mem::size_of, io::Cursor };
use bytemuck::{ Pod, Zeroable };
use byte_slice_cast::*;
use num_enum::TryFromPrimitive;
use anchor_lang::prelude::*;
use solana_program::{
    program::{ invoke_signed },
    account_info::AccountInfo,
    system_instruction,
};

extern crate slab_alloc;
use slab_alloc::{ SlabPageAlloc, CritMapHeader, CritMap, AnyNode, LeafNode, SlabVec };

extern crate decode_account;
use decode_account::parse_bpf_loader::{ parse_bpf_upgradeable_loader, BpfUpgradeableLoaderAccountType };

pub const MAX_RBAC: u32 = 1024;

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
    NetworkAdmin,           // Can create/modify other admins (program owner is always a NetworkAdmin)
    ManagerAdmin,           // Can create/modify manager approvals (processes subscriptions)
    MerchantAdmin,          // Can create/modify merchant approvals (receives subscription payments)
}

#[derive(Copy, Clone)]
#[repr(packed)]
pub struct UserRBAC {
    pub active: bool,
    pub user_key: Pubkey,
    pub role: Role,
}
unsafe impl Zeroable for UserRBAC {}
unsafe impl Pod for UserRBAC {}

impl UserRBAC {
    pub fn active(&self) -> bool {
        self.active
    }

    pub fn set_active(&mut self, new_status: bool) {
        self.active = new_status
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

#[inline]
fn index_datatype(data_type: DT) -> u16 {  // Maps only
    match data_type {
        DT::UserRBAC => DT::UserRBAC as u16,
        _ => { panic!("Invalid datatype") },
    }
}

#[inline]
fn map_len(data_type: DT) -> u32 {
    match data_type {
        DT::UserRBAC => MAX_RBAC,
        _ => 0,
    }
}

#[inline]
fn map_datatype(data_type: DT) -> u16 {  // Maps only
    match data_type {
        DT::UserRBAC => DT::UserRBACMap as u16,
        _ => { panic!("Invalid datatype") },
    }
}

#[inline]
fn map_get(pt: &mut SlabPageAlloc, data_type: DT, key: u128) -> Option<u32> {
    let cm = CritMap { slab: pt, type_id: map_datatype(data_type), capacity: map_len(data_type) };
    let rf = cm.get_key(key);
    match rf {
        None => None,
        Some(res) => Some(res.data()),
    }
}

#[inline]
fn map_set(pt: &mut SlabPageAlloc, data_type: DT, key: u128, data: u32) {
    let mut cm = CritMap { slab: pt, type_id: map_datatype(data_type), capacity: map_len(data_type) };
    let node = LeafNode::new(key, data);
    cm.insert_leaf(&node).expect("Failed to insert leaf");
}

#[inline]
fn next_index(pt: &mut SlabPageAlloc, data_type: DT) -> u32 {
    let svec = pt.header_mut::<SlabVec>(index_datatype(data_type));
    svec.next_index()
}

fn has_role(acc_auth: &AccountInfo, role: Role, key: &Pubkey) -> ProgramResult {
    let auth_data: &mut [u8] = &mut acc_auth.try_borrow_mut_data()?;
    let rd = SlabPageAlloc::new(auth_data);
    let authhash: u128 = CritMap::bytes_hash([[role as u32].as_byte_slice(), key.as_ref()].concat().as_slice());
    let authrec = map_get(rd, DT::UserRBAC, authhash);
    if ! authrec.is_some() {
        //msg!("Role not found");
        return Err(ErrorCode::AccessDenied.into());
    }
    let urec = rd.index::<UserRBAC>(DT::UserRBAC as u16, authrec.unwrap() as usize);
    if ! urec.active() {
        //msg!("Role revoked");
        return Err(ErrorCode::AccessDenied.into());
    }
    Ok(())
}

#[program]
mod net_authority {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>,
        inp_root_size: u64,
        inp_root_rent: u64
    ) -> ProgramResult {
        {
            let acc_prog = &ctx.accounts.program.to_account_info();
            let acc_pdat = &ctx.accounts.program_data.to_account_info();
            let acc_user = &ctx.accounts.program_admin.to_account_info();
            verify_program_owner(ctx.program_id, &acc_prog, &acc_pdat, &acc_user)?;
        }
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
            return Err(ErrorCode::InvalidDerivedAccount.into());
        }
        let account_signer_seeds: &[&[_]] = &[
            ctx.program_id.as_ref(),
            &[bump_seed],
        ];
        msg!("Create root data account");
        invoke_signed(
            &system_instruction::create_account(
                funder_info.key,
                data_account_info.key,
                inp_root_rent,
                inp_root_size,
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
        let root_dst: &mut [u8] = &mut root_data;
        let mut root_crs = Cursor::new(root_dst);
        ra.try_serialize(&mut root_crs)?;

        let auth_data: &mut[u8] = &mut acc_auth.try_borrow_mut_data()?;
        let rd = SlabPageAlloc::new(auth_data);
        rd.setup_page_table();
        rd.allocate::<CritMapHeader, AnyNode>(DT::UserRBACMap as u16, MAX_RBAC as usize).expect("Failed to allocate");
        rd.allocate::<SlabVec, UserRBAC>(DT::UserRBAC as u16, MAX_RBAC as usize).expect("Failed to allocate");
        Ok(())
    }

    pub fn grant(ctx: Context<UpdateRBAC>,
        inp_root_nonce: u8,
        inp_role: u32,
    ) -> ProgramResult {
        let acc_admn = &ctx.accounts.program_admin.to_account_info(); // Program owner or network admin
        let acc_root = &ctx.accounts.root_data.to_account_info();
        let acc_auth = &ctx.accounts.auth_data.to_account_info();
        let acc_rbac = &ctx.accounts.rbac_user.to_account_info();

        // Check for NetworkAdmin authority
        let admin_role = has_role(&acc_auth, Role::NetworkAdmin, acc_admn.key);
        let mut program_owner: bool = false;
        if admin_role.is_err() {
            let acc_prog = &ctx.accounts.program.to_account_info();
            let acc_pdat = &ctx.accounts.program_data.to_account_info();
            verify_program_owner(ctx.program_id, &acc_prog, &acc_pdat, &acc_admn)?;
            program_owner = true;
        }

        // Verify specified role
        let role_item = Role::try_from_primitive(inp_role);
        if role_item.is_err() {
            msg!("Invalid role: {}", inp_role.to_string());
            return Err(ErrorCode::InvalidParameters.into());
        }
        let role = role_item.unwrap();
        if role == Role::NetworkAdmin && ! program_owner {
            msg!("Reserved for program owner");
            return Err(ErrorCode::AccessDenied.into());
        }

        // Verify not assigning roles to self
        if *acc_admn.key == *acc_rbac.key {
            msg!("Cannot grant roles to self");
            return Err(ErrorCode::AccessDenied.into());
        }

        // Verify program data
        let acc_root_expected = Pubkey::create_program_address(&[ctx.program_id.as_ref(), &[inp_root_nonce]], ctx.program_id)
            .map_err(|_| ErrorCode::InvalidDerivedAccount)?;
        verify_matching_accounts(acc_root.key, &acc_root_expected, Some(String::from("Invalid root data")))?;
        verify_matching_accounts(acc_auth.key, &ctx.accounts.root_data.root_authority, Some(String::from("Invalid root authority")))?;

        let auth_data: &mut[u8] = &mut acc_auth.try_borrow_mut_data()?;
        let rd = SlabPageAlloc::new(auth_data);
        let authhash: u128 = CritMap::bytes_hash([[role as u32].as_byte_slice(), acc_rbac.key.as_ref()].concat().as_slice());

        // Check if record exists
        let authrec = map_get(rd, DT::UserRBAC, authhash);
        if authrec.is_some() {
            // Check if record is active
            let rec_idx = authrec.unwrap() as usize;
            let urec = rd.index_mut::<UserRBAC>(DT::UserRBAC as u16, rec_idx);
            if urec.active() {
                msg!("Role already active");
            } else {
                urec.set_active(true);
                msg!("Role resumed");
            }
        } else {
            // Add new record
            let rbac_idx = next_index(rd, DT::UserRBAC);
            let ur = UserRBAC {
                active: true,
                user_key: *acc_rbac.key,
                role: role,
            };
            *rd.index_mut(DT::UserRBAC as u16, rbac_idx as usize) = ur;
            map_set(rd, DT::UserRBAC, authhash, rbac_idx);
            msg!("Role granted");
        }
        Ok(())
    }

    pub fn revoke(ctx: Context<UpdateRBAC>,
        inp_root_nonce: u8,
        inp_role: u32,
    ) -> ProgramResult {
        let acc_admn = &ctx.accounts.program_admin.to_account_info(); // Program owner or network admin
        let acc_root = &ctx.accounts.root_data.to_account_info();
        let acc_auth = &ctx.accounts.auth_data.to_account_info();
        let acc_rbac = &ctx.accounts.rbac_user.to_account_info();

        // Check for NetworkAdmin authority
        let admin_role = has_role(&acc_auth, Role::NetworkAdmin, acc_admn.key);
        let mut program_owner: bool = false;
        if admin_role.is_err() {
            let acc_prog = &ctx.accounts.program.to_account_info();
            let acc_pdat = &ctx.accounts.program_data.to_account_info();
            verify_program_owner(ctx.program_id, &acc_prog, &acc_pdat, &acc_admn)?;
            program_owner = true;
        }

        // Verify specified role
        let role_item = Role::try_from_primitive(inp_role);
        if role_item.is_err() {
            msg!("Invalid role: {}", inp_role.to_string());
            return Err(ErrorCode::InvalidParameters.into());
        }
        let role = role_item.unwrap();
        if role == Role::NetworkAdmin && ! program_owner {
            msg!("Reserved for program owner");
            return Err(ErrorCode::AccessDenied.into());
        }

        // Verify program data
        let acc_root_expected = Pubkey::create_program_address(&[ctx.program_id.as_ref(), &[inp_root_nonce]], ctx.program_id)
            .map_err(|_| ErrorCode::InvalidDerivedAccount)?;
        verify_matching_accounts(acc_root.key, &acc_root_expected, Some(String::from("Invalid root data")))?;
        verify_matching_accounts(acc_auth.key, &ctx.accounts.root_data.root_authority, Some(String::from("Invalid root authority")))?;

        let auth_data: &mut[u8] = &mut acc_auth.try_borrow_mut_data()?;
        let rd = SlabPageAlloc::new(auth_data);
        let authhash: u128 = CritMap::bytes_hash([[role as u32].as_byte_slice(), acc_rbac.key.as_ref()].concat().as_slice());

        // Check if record exists
        let authrec = map_get(rd, DT::UserRBAC, authhash);
        if authrec.is_some() {
            // Check if record is active
            let rec_idx = authrec.unwrap() as usize;
            let urec = rd.index_mut::<UserRBAC>(DT::UserRBAC as u16, rec_idx);
            if urec.active() {
                urec.set_active(false);
                msg!("Role revoked");
            } else {
                msg!("Role already revoked");
            }
        } else {
            msg!("Role not found");
        }
        Ok(())
    }

    pub fn approve_merchant(ctx: Context<ApproveMerchant>,
        inp_root_nonce: u8,
        inp_fees_bps: u32,
    ) -> ProgramResult {
        let acc_admn = &ctx.accounts.merchant_admin.to_account_info(); // Merchant admin
        let acc_root = &ctx.accounts.root_data.to_account_info();
        let acc_auth = &ctx.accounts.auth_data.to_account_info();

        // Verify program data
        let acc_root_expected = Pubkey::create_program_address(&[ctx.program_id.as_ref(), &[inp_root_nonce]], ctx.program_id)
            .map_err(|_| ErrorCode::InvalidDerivedAccount)?;
        verify_matching_accounts(acc_root.key, &acc_root_expected, Some(String::from("Invalid root data")))?;
        verify_matching_accounts(acc_auth.key, &ctx.accounts.root_data.root_authority, Some(String::from("Invalid root authority")))?;

        // Check for MerchantAdmin authority
        let admin_role = has_role(&acc_auth, Role::MerchantAdmin, acc_admn.key);
        if admin_role.is_err() {
            msg!("Not merchant admin");
            return Err(ErrorCode::AccessDenied.into());
        }

        // Create approval account
        let acc_aprv = &mut ctx.accounts.merchant_approval;
        acc_aprv.active = true;
        acc_aprv.merchant_key = *ctx.accounts.merchant_key.to_account_info().key;
        acc_aprv.token_mint = *ctx.accounts.token_mint.to_account_info().key;
        acc_aprv.fees_account = *ctx.accounts.fees_account.to_account_info().key;
        acc_aprv.fees_bps = inp_fees_bps;

        Ok(())
    }

    pub fn update_merchant(ctx: Context<UpdateMerchant>,
        inp_root_nonce: u8,
        inp_fees_bps: u32,
        inp_active: bool,
    ) -> ProgramResult {
        let acc_admn = &ctx.accounts.merchant_admin.to_account_info(); // Merchant admin
        let acc_root = &ctx.accounts.root_data.to_account_info();
        let acc_auth = &ctx.accounts.auth_data.to_account_info();

        // Verify program data
        let acc_root_expected = Pubkey::create_program_address(&[ctx.program_id.as_ref(), &[inp_root_nonce]], ctx.program_id)
            .map_err(|_| ErrorCode::InvalidDerivedAccount)?;
        verify_matching_accounts(acc_root.key, &acc_root_expected, Some(String::from("Invalid root data")))?;
        verify_matching_accounts(acc_auth.key, &ctx.accounts.root_data.root_authority, Some(String::from("Invalid root authority")))?;

        // Check for MerchantAdmin authority
        let admin_role = has_role(&acc_auth, Role::MerchantAdmin, acc_admn.key);
        if admin_role.is_err() {
            msg!("Not merchant admin");
            return Err(ErrorCode::AccessDenied.into());
        }

        // Update approval account
        let acc_aprv = &mut ctx.accounts.merchant_approval;
        acc_aprv.active = inp_active;
        acc_aprv.fees_account = *ctx.accounts.fees_account.to_account_info().key;
        acc_aprv.fees_bps = inp_fees_bps;

        Ok(())
    }

    pub fn approve_manager(ctx: Context<ApproveManager>,
        inp_root_nonce: u8,
    ) -> ProgramResult {
        let acc_admn = &ctx.accounts.manager_admin.to_account_info(); // Manager admin
        let acc_root = &ctx.accounts.root_data.to_account_info();
        let acc_auth = &ctx.accounts.auth_data.to_account_info();

        // Verify program data
        let acc_root_expected = Pubkey::create_program_address(&[ctx.program_id.as_ref(), &[inp_root_nonce]], ctx.program_id)
            .map_err(|_| ErrorCode::InvalidDerivedAccount)?;
        verify_matching_accounts(acc_root.key, &acc_root_expected, Some(String::from("Invalid root data")))?;
        verify_matching_accounts(acc_auth.key, &ctx.accounts.root_data.root_authority, Some(String::from("Invalid root authority")))?;

        // Check for ManagerAdmin authority
        let admin_role = has_role(&acc_auth, Role::ManagerAdmin, acc_admn.key);
        if admin_role.is_err() {
            msg!("Not manager admin");
            return Err(ErrorCode::AccessDenied.into());
        }

        // Create approval account
        let acc_aprv = &mut ctx.accounts.manager_approval;
        acc_aprv.active = true;
        acc_aprv.manager_key = *ctx.accounts.manager_key.to_account_info().key;

        Ok(())
    }

    pub fn update_manager(ctx: Context<UpdateManager>,
        inp_root_nonce: u8,
        inp_active: bool,
    ) -> ProgramResult {
        let acc_admn = &ctx.accounts.manager_admin.to_account_info(); // Manager admin
        let acc_root = &ctx.accounts.root_data.to_account_info();
        let acc_auth = &ctx.accounts.auth_data.to_account_info();

        // Verify program data
        let acc_root_expected = Pubkey::create_program_address(&[ctx.program_id.as_ref(), &[inp_root_nonce]], ctx.program_id)
            .map_err(|_| ErrorCode::InvalidDerivedAccount)?;
        verify_matching_accounts(acc_root.key, &acc_root_expected, Some(String::from("Invalid root data")))?;
        verify_matching_accounts(acc_auth.key, &ctx.accounts.root_data.root_authority, Some(String::from("Invalid root authority")))?;

        // Check for ManagerAdmin authority
        let admin_role = has_role(&acc_auth, Role::ManagerAdmin, acc_admn.key);
        if admin_role.is_err() {
            msg!("Not manager admin");
            return Err(ErrorCode::AccessDenied.into());
        }

        // Update approval account
        let acc_aprv = &mut ctx.accounts.manager_approval;
        acc_aprv.active = inp_active;

        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    pub root_data: AccountInfo<'info>,
    #[account(init)]
    pub auth_data: AccountInfo<'info>,
    pub program: AccountInfo<'info>,
    pub program_data: AccountInfo<'info>,
    #[account(signer)]
    pub program_admin: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct UpdateRBAC<'info> {
    pub root_data: ProgramAccount<'info, RootData>,
    #[account(mut)]
    pub auth_data: AccountInfo<'info>,
    pub program: AccountInfo<'info>,
    pub program_data: AccountInfo<'info>,
    #[account(signer)]
    pub program_admin: AccountInfo<'info>,
    pub rbac_user: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct ApproveMerchant<'info> {
    pub root_data: ProgramAccount<'info, RootData>,
    pub auth_data: AccountInfo<'info>,
    #[account(signer)]
    pub merchant_admin: AccountInfo<'info>,
    #[account(init)]
    pub merchant_approval: ProgramAccount<'info, MerchantApproval>,
    pub merchant_key: AccountInfo<'info>,
    pub token_mint: AccountInfo<'info>,
    pub fees_account: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct UpdateMerchant<'info> {
    pub root_data: ProgramAccount<'info, RootData>,
    pub auth_data: AccountInfo<'info>,
    #[account(signer)]
    pub merchant_admin: AccountInfo<'info>,
    #[account(mut)]
    pub merchant_approval: ProgramAccount<'info, MerchantApproval>,
    pub fees_account: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct ApproveManager<'info> {
    pub root_data: ProgramAccount<'info, RootData>,
    pub auth_data: AccountInfo<'info>,
    #[account(signer)]
    pub manager_admin: AccountInfo<'info>,
    #[account(init)]
    pub manager_approval: ProgramAccount<'info, ManagerApproval>,
    pub manager_key: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct UpdateManager<'info> {
    pub root_data: ProgramAccount<'info, RootData>,
    pub auth_data: AccountInfo<'info>,
    #[account(signer)]
    pub manager_admin: AccountInfo<'info>,
    #[account(mut)]
    pub manager_approval: ProgramAccount<'info, ManagerApproval>,
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
    #[msg("Access denied")]
    AccessDenied,
    #[msg("Invalid parameters")]
    InvalidParameters,
    #[msg("Invalid account")]
    InvalidAccount,
    #[msg("Invalid derived account")]
    InvalidDerivedAccount,
    #[msg("Overflow")]
    Overflow,

}
