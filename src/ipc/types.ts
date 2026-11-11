export type ErrorCode =
  | "INVALID_CREDENTIALS"
  | "VAULT_LOCKED"
  | "VAULT_ALREADY_INITIALIZED"
  | "VAULT_NOT_INITIALIZED"
  | "HELLO_CANCELLED"
  | "HELLO_INVALIDATED"
  | "CONSENT_REQUIRED"
  | "VALIDATION_ERROR"
  | "BACKUP_CORRUPTED"
  | "INTERNAL_ERROR";

export interface VaultError {
  code: ErrorCode;
  message: string;
}

export type ItemType = "login" | "note" | "card";

export type CopyableField =
  | "password"
  | "username"
  | "totp"
  | "card_number"
  | "cvv"
  | "pin"
  | "note_body";

export interface VaultStatusDto {
  initialized: boolean;
  locked: boolean;
  hello_enabled: boolean;
  hello_available: boolean;
}

export interface VaultSessionInfo {
  lock_timeout_secs: number;
  clipboard_ttl_secs: number;
  hello_enabled: boolean;
}

export interface SecurityPrefsDto {
  lock_timeout_secs: number;
  clipboard_ttl_secs: number;
  hello_enabled: boolean;
  hello_available: boolean;
}

export interface FolderDto {
  id: string;
  name: string;
}

export interface CachedItemOverview {
  id: string;
  folder_id: string | null;
  item_type: ItemType;
  favorite: boolean;
  title: string;
  subtitle: string;
  urls: string[];
  tags: string[];
  updated_at: number;
}

export interface VaultIndexDto {
  folders: FolderDto[];
  items_overview: CachedItemOverview[];
}

export interface OverviewPayload {
  title: string;
  subtitle: string;
  urls: string[];
  tags: string[];
}

export interface PasswordHistoryEntry {
  password: string;
  changed_at: number;
}

export type SecretPayload =
  | {
      kind: "login";
      username: string;
      password: string;
      totp_uri: string | null;
      notes: string | null;
      password_history?: PasswordHistoryEntry[];
    }
  | {
      kind: "note";
      body: string;
    }
  | {
      kind: "card";
      cardholder_name: string;
      card_number: string;
      exp_month: string;
      exp_year: string;
      cvv: string;
      pin: string | null;
      notes: string | null;
    };

export interface TotpCodeDto {
  code: string;
  remaining_secs: number;
}

export interface ItemDetailDto {
  id: string;
  folder_id: string | null;
  item_type: ItemType;
  favorite: boolean;
  overview: OverviewPayload;
  secret: SecretPayload;
  current_totp: TotpCodeDto | null;
  created_at: number;
  updated_at: number;
}

export interface SaveItemInput {
  id?: string | null;
  folder_id: string | null;
  item_type: ItemType;
  favorite: boolean;
  overview: OverviewPayload;
  secret: SecretPayload;
}

export interface PasswordGenOptions {
  length: number;
  uppercase: boolean;
  lowercase: boolean;
  digits: boolean;
  symbols: boolean;
  exclude_ambiguous: boolean;
}

export interface GeneratedPasswordDto {
  value: string;
  entropy_bits: number;
}

export interface ImportBackupStatsDto {
  folders_imported: number;
  items_imported: number;
}

export function parseVaultError(err: unknown): VaultError {
  if (typeof err === "object" && err !== null && "code" in err && "message" in err) {
    return err as VaultError;
  }
  if (typeof err === "string") {
    try {
      const parsed = JSON.parse(err) as VaultError;
      if (parsed?.code && parsed?.message) return parsed;
    } catch {
      return { code: "INTERNAL_ERROR", message: err };
    }
  }
  return {
    code: "INTERNAL_ERROR",
    message: "Error inesperado al comunicarse con el núcleo seguro.",
  };
}
