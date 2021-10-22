//use uuid::Uuid;
use std::{ io::Cursor, result::Result as FnResult };
use bytemuck::{ Pod, Zeroable };
use byte_slice_cast::*;
use num_enum::TryFromPrimitive;
use anchor_lang::prelude::*;
use solana_program::{
    program::{ invoke_signed },
    account_info::AccountInfo,
    system_instruction
};

extern crate slab_alloc;
use slab_alloc::{ SlabPageAlloc, CritMapHeader, CritMap, AnyNode, LeafNode, SlabVec, SlabTreeError };

extern crate decode_account;
use decode_account::parse_bpf_loader::{ parse_bpf_upgradeable_loader, BpfUpgradeableLoaderAccountType };

declare_id!("7AvBUBV8X5w8dvSnMm9QuMS51mNh7dK9zDZ2W1iR2rBg");

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
    SwapDeposit,            // Can deposit to swap contracts
    SwapWithdraw,           // Can withdraw from swap contracts
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
            map_remove(rd, DT::UserRBAC, authhash).or(Err(ProgramError::from(ErrorCode::InternalError)))?;
            UserRBAC::free_index(rd, DT::UserRBAC, authrec.unwrap().slot())?;
            msg!("Atellix: Role revoked");
        } else {
            msg!("Atellix: Role not found");
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
        let ra = MerchantApproval {
            active: true,
            merchant_key: *ctx.accounts.merchant_key.to_account_info().key,
            token_mint: *ctx.accounts.token_mint.to_account_info().key,
            fees_account: *ctx.accounts.fees_account.to_account_info().key,
            fees_bps: inp_fees_bps,
            revenue: 0,
        };
        let mut aprv_data = acc_aprv.try_borrow_mut_data()?;
        let aprv_dst: &mut [u8] = &mut aprv_data;
        let mut aprv_crs = Cursor::new(aprv_dst);
        ra.try_serialize(&mut aprv_crs)?;

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

    pub fn record_revenue(ctx: Context<RecordRevenue>,
        inp_root_nonce: u8,
        inp_incoming: bool,
        inp_amount: u64,
    ) -> ProgramResult {
        let acc_admn = &ctx.accounts.revenue_admin.to_account_info(); // Revenue admin
        let acc_root = &ctx.accounts.root_data.to_account_info();
        let acc_auth = &ctx.accounts.auth_data.to_account_info();

        // Verify program data
        let acc_root_expected = Pubkey::create_program_address(&[ctx.program_id.as_ref(), &[inp_root_nonce]], ctx.program_id)
            .map_err(|_| ErrorCode::InvalidDerivedAccount)?;
        verify_matching_accounts(acc_root.key, &acc_root_expected, Some(String::from("Invalid root data")))?;
        verify_matching_accounts(acc_auth.key, &ctx.accounts.root_data.root_authority, Some(String::from("Invalid root authority")))?;

        // Check for RevenueAdmin authority
        let admin_role = has_role(&acc_auth, Role::RevenueAdmin, acc_admn.key);
        if admin_role.is_err() {
            msg!("Not revenue admin");
            return Err(ErrorCode::AccessDenied.into());
        }

        // Update approval account
        let acc_aprv = &mut ctx.accounts.merchant_approval;
        if !acc_aprv.active {
            msg!("Inactive merchant");
            return Err(ErrorCode::AccessDenied.into());
        }
        if inp_incoming {
            acc_aprv.revenue = acc_aprv.revenue.checked_add(inp_amount as u64).ok_or(ProgramError::from(ErrorCode::Overflow))?;
        } else {
            acc_aprv.revenue = acc_aprv.revenue.checked_sub(inp_amount as u64).ok_or(ProgramError::from(ErrorCode::Overflow))?;
        }

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
        let ra = ManagerApproval {
            active: true,
            manager_key: *ctx.accounts.manager_key.to_account_info().key,
        };
        let mut aprv_data = acc_aprv.try_borrow_mut_data()?;
        let aprv_dst: &mut [u8] = &mut aprv_data;
        let mut aprv_crs = Cursor::new(aprv_dst);
        ra.try_serialize(&mut aprv_crs)?;

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
    #[account(mut)]
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
    #[account(mut)]
    pub merchant_approval: AccountInfo<'info>,
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
pub struct RecordRevenue<'info> {
    pub root_data: ProgramAccount<'info, RootData>,
    pub auth_data: AccountInfo<'info>,
    #[account(signer)]
    pub revenue_admin: AccountInfo<'info>,
    #[account(mut)]
    pub merchant_approval: ProgramAccount<'info, MerchantApproval>,
}

#[derive(Accounts)]
pub struct ApproveManager<'info> {
    pub root_data: ProgramAccount<'info, RootData>,
    pub auth_data: AccountInfo<'info>,
    #[account(signer)]
    pub manager_admin: AccountInfo<'info>,
    #[account(mut)]
    pub manager_approval: AccountInfo<'info>,
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
    pub fees_bps: u32,
    pub revenue: u64,
}

impl Default for MerchantApproval {
    fn default() -> Self {
        Self {
            active: false,
            merchant_key: Pubkey::default(),
            token_mint: Pubkey::default(),
            fees_account: Pubkey::default(),
            fees_bps: 0,
            revenue: 0,
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