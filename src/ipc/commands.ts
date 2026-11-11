import { invoke } from "@tauri-apps/api/core";
import type {
  CachedItemOverview,
  CopyableField,
  ExportBackupOutput,
  FolderDto,
  GeneratedPasswordDto,
  ImportBackupStatsDto,
  ItemDetailDto,
  ItemType,
  PasswordGenOptions,
  SaveItemInput,
  SecurityPrefsDto,
  SelectedBackupFileDto,
  VaultIndexDto,
  VaultSessionInfo,
  VaultStatusDto,
} from "./types";

export const vaultCommands = {
  getVaultStatus: () => invoke<VaultStatusDto>("get_vault_status"),

  createVault: (master_password: string, ack_no_recovery: boolean) =>
    invoke<VaultSessionInfo>("create_vault", {
      input: { master_password, ack_no_recovery },
    }),

  unlockWithPassword: (master_password: string) =>
    invoke<VaultSessionInfo>("unlock_with_password", {
      input: { master_password },
    }),

  // Conectados en Fase 4 al proveedor NCrypt / Microsoft Passport KSP
  unlockWithHello: () => invoke<VaultSessionInfo>("unlock_with_hello"),
  enableWindowsHello: (master_password: string) =>
    invoke<void>("enable_windows_hello", { input: { master_password } }),
  disableWindowsHello: () => invoke<void>("disable_windows_hello"),

  lockVault: () => invoke<void>("lock_vault"),

  recordUserActivity: () => invoke<void>("record_user_activity"),

  getSecurityPrefs: () => invoke<SecurityPrefsDto>("get_security_prefs"),

  updateSecurityPrefs: (
    lock_timeout_secs: number,
    clipboard_ttl_secs: number,
    capture_protection_enabled: boolean
  ) =>
    invoke<void>("update_security_prefs", {
      input: {
        lock_timeout_secs,
        clipboard_ttl_secs,
        capture_protection_enabled,
      },
    }),

  changeMasterPassword: (current_password: string, new_password: string) =>
    invoke<{ hello_was_reset: boolean }>("change_master_password", {
      input: { current_password, new_password },
    }),

  listVaultIndex: (filters: {
    search_query?: string | null;
    folder_id?: string | null;
    item_type?: ItemType | null;
  }) =>
    invoke<VaultIndexDto>("list_vault_index", {
      input: {
        search_query: filters.search_query ?? null,
        folder_id: filters.folder_id ?? null,
        item_type: filters.item_type ?? null,
      },
    }),

  getItemDetail: (itemId: string) =>
    invoke<ItemDetailDto>("get_item_detail", { itemId }),

  saveItem: (input: SaveItemInput) =>
    invoke<CachedItemOverview>("save_item", { input }),

  deleteItem: (itemId: string) =>
    invoke<void>("delete_item", { itemId }),

  saveFolder: (name: string, id?: string | null) =>
    invoke<FolderDto>("save_folder", { input: { id: id ?? null, name } }),

  deleteFolder: (id: string) =>
    invoke<void>("delete_folder", { id }),

  generatePassword: (options: PasswordGenOptions) =>
    invoke<GeneratedPasswordDto>("generate_password", { options }),

  copyItemField: (item_id: string, field: CopyableField) =>
    invoke<{ expires_in_secs: number }>("copy_item_field", {
      input: { item_id, field },
    }),

  copyTextProtected: (text: string, field = "generated_password") =>
    invoke<{ expires_in_secs: number }>("copy_text_protected", {
      input: { text, field },
    }),

  clearClipboardNow: () => invoke<void>("clear_clipboard_now"),

  selectRestoreBackupFile: () =>
    invoke<SelectedBackupFileDto>("select_restore_backup_file"),

  exportEncryptedBackup: (
    master_password: string,
    backup_password: string,
    skip_corrupted = false
  ) =>
    invoke<ExportBackupOutput>("export_encrypted_backup", {
      input: { master_password, backup_password, skip_corrupted },
    }),

  restoreEncryptedBackup: (
    backup_password: string,
    new_master_password: string,
    ack_no_recovery: boolean
  ) =>
    invoke<VaultSessionInfo>("restore_encrypted_backup", {
      input: {
        backup_password,
        new_master_password,
        ack_no_recovery,
      },
    }),

  importEncryptedBackup: (backup_password: string) =>
    invoke<ImportBackupStatsDto>("import_encrypted_backup", {
      input: { backup_password },
    }),
};
