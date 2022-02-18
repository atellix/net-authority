use crate::program::NetAuthority;
use std::{ result::Result as FnResult };
use bytemuck::{ Pod, Zeroable };
use byte_slice_cast::*;
use num_enum::TryFromPrimitive;
use anchor_lang::prelude::*;
use solana_program::{ account_info::AccountInfo };

extern crate slab_alloc;
use slab_alloc::{ SlabPageAlloc, CritMapHeader, CritMap, AnyNode, LeafNode, SlabVec, SlabTreeError };

declare_id!("3Ss3tq7W2q5hgh9DcJArZkHaWUai1Q5CfZymS5vAeGSn");

pub const VERSION_MAJOR: u32 = 1;
pub const VERSION_MINOR: u32 = 0;
pub const VERSION_PATCH: u32 = 0;

pub const MAX_RBAC: u32 = 128;

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
    RevenueAdmin,           // Can register merchant revenue (trusted contract internal PDAs)
}

#[derive(Copy, Clone)]
#[repr(packed)]
pub struct UserRBAC {
    pub role: Role,
    pub free: u32,
}
unsafe impl Zeroable for UserRBAC {}
unsafe impl Pod for UserRBAC {}

impl UserRBAC {
    pub fn role(&self) -> Role {
        self.role
    }

    pub fn free(&self) -> u32 {
        self.free
    }

    pub fn set_free(&mut self, new_free: u32) {
        self.free = new_free
    }

    fn next_index(pt: &mut SlabPageAlloc, data_type: DT) -> FnResult<u32, ProgramError> {
        let svec = pt.header_mut::<SlabVec>(index_datatype(data_type));
        let free_top = svec.free_top();
        if free_top == 0 { // Empty free list
            return Ok(svec.next_index());
        }
        let free_index = free_top.checked_sub(1).ok_or(ProgramError::from(ErrorCode::Overflow))?;
        let index_act = pt.index::<UserRBAC>(index_datatype(data_type), free_index as usize);
        let index_ptr = index_act.free();
        pt.header_mut::<SlabVec>(index_datatype(data_type)).set_free_top(index_ptr);
        Ok(free_index)
    }

    fn free_index(pt: &mut SlabPageAlloc, data_type: DT, idx: u32) -> ProgramResult {
        let free_top = pt.header::<SlabVec>(index_datatype(data_type)).free_top();
        pt.index_mut::<UserRBAC>(index_datatype(data_type), idx as usize).set_free(free_top);
        let new_top = idx.checked_add(1).ok_or(ProgramError::from(ErrorCode::Overflow))?;
        pt.header_mut::<SlabVec>(index_datatype(data_type)).set_free_top(new_top);
        Ok(())
    }
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
fn map_get(pt: &mut SlabPageAlloc, data_type: DT, key: u128) -> Option<LeafNode> {
    let cm = CritMap { slab: pt, type_id: map_datatype(data_type), capacity: map_len(data_type) };
    let rf = cm.get_key(key);
    match rf {
        None => None,
        Some(res) => Some(res.clone()),
    }
}

#[inline]
fn map_insert(pt: &mut SlabPageAlloc, data_type: DT, node: &LeafNode) -> FnResult<(), SlabTreeError> {
    let mut cm = CritMap { slab: pt, type_id: map_datatype(data_type), capacity: map_len(data_type) };
    let res = cm.insert_leaf(node);
    match res {
        Err(SlabTreeError::OutOfSpace) => {
            //msg!("Atellix: Out of space...");
            return Err(SlabTreeError::OutOfSpace)
        },
        _  => Ok(())
    }
}

#[inline]
fn map_remove(pt: &mut SlabPageAlloc, data_type: DT, key: u128) -> FnResult<(), SlabTreeError> {
    let mut cm = CritMap { slab: pt, type_id: map_datatype(data_type), capacity: map_len(data_type) };
    cm.remove_by_key(key).ok_or(SlabTreeError::NotFound)?;
    Ok(())
}

fn has_role(acc_auth: &AccountInfo, role: Role, key: &Pubkey) -> ProgramResult {
    let auth_data: &mut [u8] = &mut acc_auth.try_borrow_mut_data()?;
    let rd = SlabPageAlloc::new(auth_data);
    let authhash: u128 = CritMap::bytes_hash([[role as u32].as_byte_slice(), key.as_ref()].concat().as_slice());
    let authrec = map_get(rd, DT::UserRBAC, authhash);
    if ! authrec.is_some() {
        return Err(ErrorCode::AccessDenied.into());
    }
    if authrec.unwrap().owner() != *key {
        msg!("User key does not match signer");
        return Err(ErrorCode::AccessDenied.into());
    }
    let urec = rd.index::<UserRBAC>(DT::UserRBAC as u16, authrec.unwrap().slot() as usize);
    if urec.role() != role {
        msg!("Role does not match");
        return Err(ErrorCode::AccessDenied.into());
    }
    Ok(())
}

#[program]
mod net_authority {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> ProgramResult {
        let rt = &mut ctx.accounts.root_data;
        rt.root_authority = ctx.accounts.auth_data.key();

        let auth_data: &mut[u8] = &mut ctx.accounts.auth_data.try_borrow_mut_data()?;
        let rd = SlabPageAlloc::new(auth_data);
        rd.setup_page_table();
        rd.allocate::<CritMapHeader, AnyNode>(DT::UserRBACMap as u16, MAX_RBAC as usize).expect("Failed to allocate");
        rd.allocate::<SlabVec, UserRBAC>(DT::UserRBAC as u16, MAX_RBAC as usize).expect("Failed to allocate");

        Ok(())
    }

    pub fn store_metadata(ctx: Context<UpdateMetadata>,
        inp_program_name: String,
        inp_developer_name: String,
        inp_developer_url: String,
        inp_source_url: String,
        inp_verify_url: String,
    ) -> ProgramResult {
        let md = &mut ctx.accounts.program_info;
        md.semvar_major = VERSION_MAJOR;
        md.semvar_minor = VERSION_MINOR;
        md.semvar_patch = VERSION_PATCH;
        md.program = ctx.accounts.program.key();
        md.program_name = inp_program_name;
        md.developer_name = inp_developer_name;
        md.developer_url = inp_developer_url;
        md.source_url = inp_source_url;
        md.verify_url = inp_verify_url;
        msg!("Program: {}", ctx.accounts.program.key.to_string());
        msg!("Program Name: {}", md.program_name.as_str());
        msg!("Version: {}.{}.{}", VERSION_MAJOR.to_string(), VERSION_MINOR.to_string(), VERSION_PATCH.to_string());
        msg!("Developer Name: {}", md.developer_name.as_str());
        msg!("Developer URL: {}", md.developer_url.as_str());
        msg!("Source URL: {}", md.source_url.as_str());
        msg!("Verify URL: {}", md.verify_url.as_str());
        Ok(())
    }

    pub fn grant(ctx: Context<UpdateRBAC>,
        _inp_root_nonce: u8,
        inp_role: u32,
    ) -> ProgramResult {
        let acc_rbac = &ctx.accounts.rbac_user.to_account_info();
        let acc_admn = &ctx.accounts.program_admin.to_account_info();
        let acc_auth = &ctx.accounts.auth_data.to_account_info();

        // Check for NetworkAdmin authority
        let admin_role = has_role(&acc_auth, Role::NetworkAdmin, acc_admn.key);
        let mut program_owner: bool = false;
        if admin_role.is_err() {
            let acc_pdat = &ctx.accounts.program_data;
            verify_matching_accounts(&acc_pdat.upgrade_authority_address.unwrap(), acc_admn.key, Some(String::from("Invalid program owner")))?;
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

        let auth_data: &mut[u8] = &mut acc_auth.try_borrow_mut_data()?;
        let rd = SlabPageAlloc::new(auth_data);
        let authhash: u128 = CritMap::bytes_hash([[role as u32].as_byte_slice(), acc_rbac.key.as_ref()].concat().as_slice());

        // Check if record exists
        let authrec = map_get(rd, DT::UserRBAC, authhash);
        if authrec.is_some() {
            msg!("Atellix: Role already active");
        } else {
            // Add new record
            let new_item = map_insert(rd, DT::UserRBAC, &LeafNode::new(authhash, 0, acc_rbac.key));
            if new_item.is_err() {
                msg!("Unable to insert role");
                return Err(ErrorCode::InternalError.into());
            }
            let rbac_idx = UserRBAC::next_index(rd, DT::UserRBAC)?;
            let mut cm = CritMap { slab: rd, type_id: map_datatype(DT::UserRBAC), capacity: map_len(DT::UserRBAC) };
            cm.get_key_mut(authhash).unwrap().set_slot(rbac_idx);
            *rd.index_mut(DT::UserRBAC as u16, rbac_idx as usize) = UserRBAC { role: role, free: 0 };
            msg!("Atellix: Role granted");
        }
        Ok(())
    }

    pub fn revoke(ctx: Context<UpdateRBAC>,
        _inp_root_nonce: u8,
        inp_role: u32,
    ) -> ProgramResult {
        let acc_admn = &ctx.accounts.program_admin.to_account_info(); // Program owner or network admin
        let acc_auth = &ctx.accounts.auth_data.to_account_info();
        let acc_rbac = &ctx.accounts.rbac_user.to_account_info();

        // Check for NetworkAdmin authority
        let admin_role = has_role(&acc_auth, Role::NetworkAdmin, acc_admn.key);
        let mut program_owner: bool = false;
        if admin_role.is_err() {
            let acc_pdat = &ctx.accounts.program_data;
            verify_matching_accounts(&acc_pdat.upgrade_authority_address.unwrap(), acc_admn.key, Some(String::from("Invalid program owner")))?;
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

        let auth_data: &mut[u8] = &mut acc_auth.try_borrow_mut_data()?;
        let rd = SlabPageAlloc::new(auth_data);
        let authhash: u128 = CritMap::bytes_hash([[role as u32].as_byte_slice(), acc_rbac.key.as_ref()].concat().as_slice());

        // Check if record exists
        let authrec = map_get(rd, DT::UserRBAC, authhash);
        if authrec.is_some() {
            map_remove(rd, DT::UserRBAC, authhash).or(Err(ProgramError::from(ErrorCode::InternalError)))?;
            UserRBAC::free_index(rd, DT::UserRBAC, authrec.unwrap().slot())?;
            msg!("Atellix: Role revoked");
        } else {
            msg!("Atellix: Role not found");
        }
        Ok(())
    }

    pub fn approve_merchant(ctx: Context<ApproveMerchant>,
        _inp_root_nonce: u8,
        inp_fees_bps: u32,
    ) -> ProgramResult {
        let acc_admn = &ctx.accounts.merchant_admin.to_account_info(); // Merchant admin
        let acc_auth = &ctx.accounts.auth_data.to_account_info();

        // Check for MerchantAdmin authority
        let admin_role = has_role(&acc_auth, Role::MerchantAdmin, acc_admn.key);
        if admin_role.is_err() {
            msg!("Not merchant admin");
            return Err(ErrorCode::AccessDenied.into());
        }

        // Create approval account
        let aprv = &mut ctx.accounts.merchant_approval;
        aprv.active = true;
        aprv.merchant_key = *ctx.accounts.merchant_key.to_account_info().key;
        aprv.token_mint = *ctx.accounts.token_mint.to_account_info().key;
        aprv.fees_account = *ctx.accounts.fees_account.to_account_info().key;
        aprv.revenue_admin = *ctx.accounts.revenue_admin.to_account_info().key;
        aprv.swap_admin = *ctx.accounts.swap_admin.to_account_info().key;
        aprv.fees_bps = inp_fees_bps;
        aprv.revenue = 0;
        aprv.tx_count = 0;

        Ok(())
    }

    pub fn update_merchant(ctx: Context<UpdateMerchant>,
        _inp_root_nonce: u8,
        inp_fees_bps: u32,
        inp_active: bool,
    ) -> ProgramResult {
        let acc_admn = &ctx.accounts.merchant_admin.to_account_info(); // Merchant admin
        let acc_auth = &ctx.accounts.auth_data.to_account_info();

        // Check for MerchantAdmin authority
        let admin_role = has_role(&acc_auth, Role::MerchantAdmin, acc_admn.key);
        if admin_role.is_err() {
            msg!("Not merchant admin");
            return Err(ErrorCode::AccessDenied.into());
        }

        // Update approval account
        let aprv = &mut ctx.accounts.merchant_approval;
        aprv.active = inp_active;
        aprv.fees_account = *ctx.accounts.fees_account.to_account_info().key;
        aprv.fees_bps = inp_fees_bps;
        aprv.revenue_admin = *ctx.accounts.revenue_admin.to_account_info().key;
        aprv.swap_admin = *ctx.accounts.swap_admin.to_account_info().key;

        Ok(())
    }

    pub fn close_merchant_approval(ctx: Context<CloseMerchantApproval>,
        _inp_root_nonce: u8,
    ) -> ProgramResult {
        let acc_admn = &ctx.accounts.merchant_admin.to_account_info();  // Merchant admin
        let acc_auth = &ctx.accounts.auth_data.to_account_info();

        // Check for MerchantAdmin authority
        let admin_role = has_role(&acc_auth, Role::MerchantAdmin, acc_admn.key);
        if admin_role.is_err() {
            msg!("Not merchant admin");
            return Err(ErrorCode::AccessDenied.into());
        }

        msg!("Closed Merchant Approval: {}", ctx.accounts.merchant_approval.to_account_info().key.to_string());
        Ok(())
    }

    pub fn store_merchant_details(ctx: Context<UpdateMerchantDetails>,
        _inp_root_nonce: u8,
        inp_active: bool,
        inp_merchant_name: String,
        inp_merchant_url: String,
        inp_verify_url: String,
    ) -> ProgramResult {
        let acc_admn = &ctx.accounts.merchant_admin.to_account_info();  // Merchant admin
        let acc_auth = &ctx.accounts.auth_data.to_account_info();

        // Check for MerchantAdmin authority
        let admin_role = has_role(&acc_auth, Role::MerchantAdmin, acc_admn.key);
        if admin_role.is_err() {
            msg!("Not merchant admin");
            return Err(ErrorCode::AccessDenied.into());
        }

        let md = &mut ctx.accounts.merchant_info;
        md.active = inp_active;
        md.merchant_key = *ctx.accounts.merchant_key.to_account_info().key;
        md.merchant_name = inp_merchant_name;
        md.merchant_url = inp_merchant_url;
        md.verify_url = inp_verify_url;
        msg!("Merchant Name: {}", md.merchant_name.as_str());
        msg!("Merchant Key: {}", ctx.accounts.merchant_key.key.to_string());
        msg!("Merchant URL: {}", md.merchant_url.as_str());
        msg!("Verify URL: {}", md.verify_url.as_str());
        msg!("Active: {}", md.active);
        Ok(())
    }

    pub fn close_merchant_details(ctx: Context<CloseMerchantDetails>,
        _inp_root_nonce: u8,
    ) -> ProgramResult {
        let acc_admn = &ctx.accounts.merchant_admin.to_account_info();  // Merchant admin
        let acc_auth = &ctx.accounts.auth_data.to_account_info();

        // Check for MerchantAdmin authority
        let admin_role = has_role(&acc_auth, Role::MerchantAdmin, acc_admn.key);
        if admin_role.is_err() {
            msg!("Not merchant admin");
            return Err(ErrorCode::AccessDenied.into());
        }

        msg!("Closed Merchant Details: {}", ctx.accounts.merchant_info.to_account_info().key.to_string());
        Ok(())
    }

    pub fn record_revenue(ctx: Context<RecordRevenue>,
        inp_incoming: bool,
        inp_amount: u64,
    ) -> ProgramResult {
        let acc_admn = &ctx.accounts.revenue_admin.to_account_info(); // Revenue admin
        //msg!("Atellix: Update merchant revenue: {}", inp_amount.to_string());

        // Update approval account
        let acc_aprv = &mut ctx.accounts.merchant_approval;
        if !acc_aprv.active {
            msg!("Inactive merchant");
            return Err(ErrorCode::AccessDenied.into());
        }
        if inp_incoming {
            verify_matching_accounts(&acc_aprv.revenue_admin, acc_admn.key, Some(String::from("Invalid revenue admin")))?;
            acc_aprv.revenue = acc_aprv.revenue.checked_add(inp_amount as u64).ok_or(ProgramError::from(ErrorCode::Overflow))?;
        } else {
            verify_matching_accounts(&acc_aprv.swap_admin, acc_admn.key, Some(String::from("Invalid swap admin")))?;
            acc_aprv.revenue = acc_aprv.revenue.checked_sub(inp_amount as u64).ok_or(ProgramError::from(ErrorCode::Overflow))?;
        }

        // Increment transaction counter
        acc_aprv.tx_count = acc_aprv.tx_count.checked_add(1).ok_or(ProgramError::from(ErrorCode::Overflow))?;

        Ok(())
    }

    pub fn approve_manager(ctx: Context<ApproveManager>,
        _inp_root_nonce: u8,
    ) -> ProgramResult {
        let acc_admn = &ctx.accounts.manager_admin.to_account_info(); // Manager admin
        let acc_auth = &ctx.accounts.auth_data.to_account_info();

        // Check for ManagerAdmin authority
        let admin_role = has_role(&acc_auth, Role::ManagerAdmin, acc_admn.key);
        if admin_role.is_err() {
            msg!("Not manager admin");
            return Err(ErrorCode::AccessDenied.into());
        }

        // Create approval account
        let aprv = &mut ctx.accounts.manager_approval;
        aprv.active = true;
        aprv.manager_key = *ctx.accounts.manager_key.to_account_info().key;

        Ok(())
    }

    pub fn update_manager(ctx: Context<UpdateManager>,
        _inp_root_nonce: u8,
        inp_active: bool,
    ) -> ProgramResult {
        let acc_admn = &ctx.accounts.manager_admin.to_account_info(); // Manager admin
        let acc_auth = &ctx.accounts.auth_data.to_account_info();

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

    pub fn close_manager_approval(ctx: Context<CloseManagerApproval>,
        _inp_root_nonce: u8,
    ) -> ProgramResult {
        let acc_admn = &ctx.accounts.manager_admin.to_account_info();  // Merchant admin
        let acc_auth = &ctx.accounts.auth_data.to_account_info();

        // Check for MerchantAdmin authority
        let admin_role = has_role(&acc_auth, Role::ManagerAdmin, acc_admn.key);
        if admin_role.is_err() {
            msg!("Not manager admin");
            return Err(ErrorCode::AccessDenied.into());
        }

        msg!("Closed Manager Approval: {}", ctx.accounts.manager_approval.to_account_info().key.to_string());
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, seeds = [program_id.as_ref()], bump, payer = program_admin)]
    pub root_data: Account<'info, RootData>,
    #[account(zero)]
    pub auth_data: UncheckedAccount<'info>,
    #[account(constraint = program.programdata_address() == Some(program_data.key()))]
    pub program: Program<'info, NetAuthority>,
    #[account(constraint = program_data.upgrade_authority_address == Some(program_admin.key()))]
    pub program_data: Account<'info, ProgramData>,
    #[account(mut)]
    pub program_admin: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpdateMetadata<'info> {
    #[account(constraint = program.programdata_address() == Some(program_data.key()))]
    pub program: Program<'info, NetAuthority>,
    #[account(constraint = program_data.upgrade_authority_address == Some(program_admin.key()))]
    pub program_data: Account<'info, ProgramData>,
    #[account(mut)]
    pub program_admin: Signer<'info>,
    #[account(init_if_needed, seeds = [program_id.as_ref(), b"metadata"], bump, payer = program_admin, space = 584)]
    pub program_info: Account<'info, ProgramMetadata>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(_inp_root_nonce: u8)]
pub struct UpdateRBAC<'info> {
    #[account(seeds = [program_id.as_ref()], bump = _inp_root_nonce)]
    pub root_data: Account<'info, RootData>,
    #[account(mut, constraint = root_data.root_authority == auth_data.key())]
    pub auth_data: UncheckedAccount<'info>,
    #[account(constraint = program.programdata_address() == Some(program_data.key()))]
    pub program: Program<'info, NetAuthority>,
    pub program_data: Account<'info, ProgramData>,
    #[account(mut)]
    pub program_admin: Signer<'info>,
    pub rbac_user: AccountInfo<'info>,
}

#[derive(Accounts)]
#[instruction(_inp_root_nonce: u8)]
pub struct ApproveMerchant<'info> {
    #[account(seeds = [program_id.as_ref()], bump = _inp_root_nonce)]
    pub root_data: Account<'info, RootData>,
    #[account(constraint = root_data.root_authority == auth_data.key())]
    pub auth_data: UncheckedAccount<'info>,
    #[account(mut)]
    pub merchant_admin: Signer<'info>,
    #[account(init, payer = merchant_admin)]
    pub merchant_approval: Account<'info, MerchantApproval>,
    pub merchant_key: UncheckedAccount<'info>,
    pub token_mint: UncheckedAccount<'info>,
    pub fees_account: UncheckedAccount<'info>,
    pub revenue_admin: UncheckedAccount<'info>,
    pub swap_admin: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(_inp_root_nonce: u8)]
pub struct UpdateMerchant<'info> {
    #[account(seeds = [program_id.as_ref()], bump = _inp_root_nonce)]
    pub root_data: Account<'info, RootData>,
    #[account(constraint = root_data.root_authority == auth_data.key())]
    pub auth_data: UncheckedAccount<'info>,
    #[account(mut)]
    pub merchant_admin: Signer<'info>,
    #[account(mut)]
    pub merchant_approval: Account<'info, MerchantApproval>,
    pub fees_account: UncheckedAccount<'info>,
    pub revenue_admin: UncheckedAccount<'info>,
    pub swap_admin: UncheckedAccount<'info>,
}

#[derive(Accounts)]
#[instruction(_inp_root_nonce: u8)]
pub struct CloseMerchantApproval<'info> {
    #[account(seeds = [program_id.as_ref()], bump = _inp_root_nonce)]
    pub root_data: Account<'info, RootData>,
    #[account(constraint = root_data.root_authority == auth_data.key())]
    pub auth_data: UncheckedAccount<'info>,
    #[account(mut)]
    pub merchant_admin: Signer<'info>,
    #[account(mut)]
    pub fee_receiver: Signer<'info>,
    #[account(mut, close = fee_receiver)]
    pub merchant_approval: Account<'info, MerchantApproval>,
}

#[derive(Accounts)]
#[instruction(_inp_root_nonce: u8)]
pub struct UpdateMerchantDetails<'info> {
    #[account(seeds = [program_id.as_ref()], bump = _inp_root_nonce)]
    pub root_data: Account<'info, RootData>,
    #[account(constraint = root_data.root_authority == auth_data.key())]
    pub auth_data: UncheckedAccount<'info>,
    #[account(mut)]
    pub fee_payer: Signer<'info>,
    #[account(mut)]
    pub merchant_admin: Signer<'info>,
    pub merchant_key: UncheckedAccount<'info>,
    #[account(init_if_needed, payer = fee_payer, seeds = [merchant_key.key.as_ref(), b"merchant-details"], bump, space = 373)]
    pub merchant_info: Account<'info, MerchantDetails>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(_inp_root_nonce: u8)]
pub struct CloseMerchantDetails<'info> {
    #[account(seeds = [program_id.as_ref()], bump = _inp_root_nonce)]
    pub root_data: Account<'info, RootData>,
    #[account(constraint = root_data.root_authority == auth_data.key())]
    pub auth_data: UncheckedAccount<'info>,
    #[account(mut)]
    pub merchant_admin: Signer<'info>,
    #[account(mut)]
    pub fee_receiver: Signer<'info>,
    #[account(mut, close = fee_receiver)]
    pub merchant_info: Account<'info, MerchantDetails>,
}

#[derive(Accounts)]
pub struct RecordRevenue<'info> {
    pub revenue_admin: Signer<'info>,
    #[account(mut)]
    pub merchant_approval: Account<'info, MerchantApproval>,
}

#[derive(Accounts)]
#[instruction(_inp_root_nonce: u8)]
pub struct ApproveManager<'info> {
    #[account(seeds = [program_id.as_ref()], bump = _inp_root_nonce)]
    pub root_data: Account<'info, RootData>,
    #[account(constraint = root_data.root_authority == auth_data.key())]
    pub auth_data: UncheckedAccount<'info>,
    #[account(mut)]
    pub manager_admin: Signer<'info>,
    #[account(init, payer = manager_admin)]
    pub manager_approval: Account<'info, ManagerApproval>,
    pub manager_key: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(_inp_root_nonce: u8)]
pub struct UpdateManager<'info> {
    #[account(seeds = [program_id.as_ref()], bump = _inp_root_nonce)]
    pub root_data: Account<'info, RootData>,
    #[account(constraint = root_data.root_authority == auth_data.key())]
    pub auth_data: UncheckedAccount<'info>,
    #[account(signer)]
    pub manager_admin: AccountInfo<'info>,
    #[account(mut)]
    pub manager_approval: Account<'info, ManagerApproval>,
}

#[derive(Accounts)]
#[instruction(_inp_root_nonce: u8)]
pub struct CloseManagerApproval<'info> {
    #[account(seeds = [program_id.as_ref()], bump = _inp_root_nonce)]
    pub root_data: Account<'info, RootData>,
    #[account(constraint = root_data.root_authority == auth_data.key())]
    pub auth_data: UncheckedAccount<'info>,
    #[account(mut)]
    pub manager_admin: Signer<'info>,
    #[account(mut)]
    pub fee_receiver: Signer<'info>,
    #[account(mut, close = fee_receiver)]
    pub manager_approval: Account<'info, ManagerApproval>,
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

impl Default for RootData {
    fn default() -> Self {
        Self {
            root_authority: Pubkey::default(),
        }
    }
}

#[account]
pub struct MerchantApproval {
    pub active: bool,
    pub merchant_key: Pubkey,
    pub token_mint: Pubkey,
    pub fees_account: Pubkey,
    pub revenue_admin: Pubkey,
    pub swap_admin: Pubkey,
    pub fees_bps: u32,
    pub revenue: u64,
    pub tx_count: u64,
}

impl Default for MerchantApproval {
    fn default() -> Self {
        Self {
            active: false,
            merchant_key: Pubkey::default(),
            token_mint: Pubkey::default(),
            fees_account: Pubkey::default(),
            revenue_admin: Pubkey::default(),
            swap_admin: Pubkey::default(),
            fees_bps: 0,
            revenue: 0,
            tx_count: 0,
        }
    }
}

#[account]
pub struct ManagerApproval {
    pub active: bool,
    pub manager_key: Pubkey,
}

impl Default for ManagerApproval {
    fn default() -> Self {
        Self {
            active: false,
            manager_key: Pubkey::default(),
        }
    }
}

#[account]
#[derive(Default)]
pub struct MerchantDetails {
    pub active: bool,
    pub merchant_key: Pubkey,
    pub merchant_name: String,  // Max len 64
    pub merchant_url: String,   // Max len 128
    pub verify_url: String,     // Max len 128
}
// 8 + 1 + 32 + (4 * 3) + 64 + (128 * 2)
// Data length (with discrim): 373 bytes

#[account]
pub struct ProgramMetadata {
    pub semvar_major: u32,
    pub semvar_minor: u32,
    pub semvar_patch: u32,
    pub program: Pubkey,
    pub program_name: String,   // Max len 64
    pub developer_name: String, // Max len 64
    pub developer_url: String,  // Max len 128
    pub source_url: String,     // Max len 128
    pub verify_url: String,     // Max len 128
}
// 8 + (4 * 3) + 32 + (4 * 5) + (64 * 2) + (128 * 3)
// Data length (with discrim): 584 bytes

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
    #[msg("Internal error")]
    InternalError,
    #[msg("Overflow")]
    Overflow,
}
